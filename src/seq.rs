// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 数字字面量提升：同一作用域里重复出现的数字，抽成一个 `local` 变量复用。
//!
//! 用户 2026-11-18 的优化要求：
//! > 同一作用域里的一个数字如果超过 2 个（比如 1 和 1），就用一个 local 变量储存起来，
//! > 这样可以节省空间。
//!
//! 实现要点（纯文本层，跑在 RadixSieve 之后、`promote_entry` 之前）：
//!
//! 1. 用 `Reshape::Lexer::lex` 切词（已能正确处理短/长字符串、`t.5` 这类数字索引）；
//! 2. 以**函数**为作用域单位统计：同一个函数体（顶层 chunk 算一个）里，
//!    同一个数值的字面量出现 ≥ `min_count`（默认 3）次，就抽成一个局部变量；
//! 3. 声明插在该函数体的第一条语句之前；顶层则插在文件最前面；
//! 4. 变量名从「全文都没出现过的 1~2 字符标识符」里挑，
//!    所以既不会遮蔽任何东西，也不需要再过一遍重命名；
//! 5. 只有当「省下的字节 > 声明本身的字节」时才提升 —— 否则纯属增大体积
//!    （例如 `1` 只占 1 字节，换成变量反而更长，这类会跳过）。
//!
//! 语义安全：
//! - 声明在函数体最前，函数内所有引用都在其后；
//! - 只做一次绑定、块内没有任何赋值给它（名字全文唯一，不会被别处赋值）；
//! - 负数不参与：`-` 是独立 token，`x-16` 只会替换 `16`，得到 `x-名字`，值不变；
//! - `1.5`、`1e10`、`1..2`、`t.5` 一律跳过。

use std::collections::{HashMap, HashSet};

use crate::VM::Reshape::Lexer::{lex, Tok, KIND_NUM, KIND_SYM, KIND_WORD};

/// 把数字字面量（含 `_` 与 `0x`/`0B` 前缀）解析成整数；不能精确解析的返回 None。
fn parse_int(text: &str) -> Option<i128> {
    let t: String = text.chars().filter(|&c| c != '_').collect();
    let lower = t.to_ascii_lowercase();
    if let Some(body) = lower.strip_prefix("0x") {
        return i128::from_str_radix(body, 16).ok();
    }
    if let Some(body) = lower.strip_prefix("0b") {
        return i128::from_str_radix(body, 2).ok();
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        // 小数 / 指数 / 十六进制浮点：一律不碰
        return None;
    }
    t.parse::<i128>().ok()
}

/// 这个数字 token 是不是一个真正的「数值表达式」（而不是 `t.5` 那种索引键）。
fn is_plain_number(toks: &[Tok], i: usize) -> bool {
    if i > 0 {
        let prev = &toks[i - 1];
        if prev.kind == KIND_SYM && (prev.text == "." || prev.text == ":") {
            return false;
        }
        if prev.kind == KIND_NUM {
            return false;
        }
    }
    if i + 1 < toks.len() && toks[i + 1].text.starts_with('.') {
        // `1..2`、`1.5` 之类
        return false;
    }
    true
}

/// 标记「属于 for/while 的 do」（`for i=1,n do` —— 它不单独配对一个 `end`）。
fn owned_do_set(toks: &[Tok]) -> HashSet<usize> {
    let m = toks.len();
    let mut owned: HashSet<usize> = HashSet::new();
    for i in 0..m {
        if toks[i].kind == KIND_WORD && (toks[i].text == "for" || toks[i].text == "while") {
            let mut p = i + 1;
            let mut pd = 0i32;
            while p < m {
                let t = &toks[p];
                if t.kind == KIND_SYM {
                    match t.text.as_str() {
                        "(" | "[" | "{" => pd += 1,
                        ")" | "]" | "}" => pd -= 1,
                        _ => {}
                    }
                }
                if t.kind == KIND_WORD && t.text == "do" && pd <= 0 {
                    owned.insert(p);
                    break;
                }
                p += 1;
            }
        }
    }
    owned
}

/// 为每个 token 求「所属函数」的编号（最外层 chunk = 0）。
fn func_of_token(toks: &[Tok]) -> Vec<usize> {
    let n = toks.len();
    let owned = owned_do_set(toks);
    let mut out = vec![0usize; n];
    // 栈里存的是「进入该块时的函数编号」
    let mut stack: Vec<usize> = vec![0];
    let mut cur = 0usize;
    let mut next_id = 1usize;
    for i in 0..n {
        let t = &toks[i];
        if t.kind == KIND_WORD {
            match t.text.as_str() {
                "end" | "until" => {
                    if stack.len() > 1 {
                        stack.pop();
                        cur = *stack.last().unwrap();
                    }
                    out[i] = cur;
                    continue;
                }
                _ => {}
            }
        }
        out[i] = cur;
        if t.kind == KIND_WORD {
            match t.text.as_str() {
                "function" => {
                    next_id += 1;
                    stack.push(cur);
                    cur = next_id - 1;
                }
                "if" | "for" | "while" | "repeat" => {
                    stack.push(cur);
                }
                "do" => {
                    if !owned.contains(&i) {
                        stack.push(cur);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// 函数体的插入点：参数表 `)` 之后的第一个 token。
/// 返回 None 表示函数体为空（`function()end`）或定位失败。
fn body_head(toks: &[Tok], func_tok: usize) -> Option<usize> {
    let n = toks.len();
    let mut i = func_tok + 1;
    // 跳过 `name` / `:` / `.` 链，找到参数表的 `(`
    while i < n && !(toks[i].kind == KIND_SYM && toks[i].text == "(") {
        if toks[i].kind == KIND_WORD && toks[i].text == "end" {
            return None;
        }
        i += 1;
    }
    if i >= n {
        return None;
    }
    let mut depth = 0i32;
    while i < n {
        if toks[i].kind == KIND_SYM {
            match toks[i].text.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    if depth == 0 {
                        let head = i + 1;
                        if head >= n {
                            return None;
                        }
                        if toks[head].kind == KIND_WORD && toks[head].text == "end" {
                            return None; // 空函数体
                        }
                        return Some(head);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// 挑一个全文都没出现过的 1~2 字符标识符。
fn fresh_short_name(used: &HashSet<String>, taken: &mut HashSet<String>, pref_len: usize) -> Option<String> {
    const KEYWORDS: [&str; 22] = [
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local",
        "nil", "not", "or", "repeat", "return", "then", "true", "until", "while", "goto",
    ];
    let first: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_".chars().collect();
    let rest: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789".chars().collect();
    // 先试 1 字符，再试 2 字符
    for len in pref_len..=2 {
        for &c in &first {
            let cand: String = if len == 1 {
                c.to_string()
            } else {
                continue;
            };
            if cand == "_" {
                continue;
            }
            if used.contains(&cand) || taken.contains(&cand) || KEYWORDS.contains(&cand.as_str()) {
                continue;
            }
            taken.insert(cand.clone());
            return Some(cand);
        }
    }
    for &a in &first {
        for &b in &rest {
            let cand: String = format!("{a}{b}");
            if used.contains(&cand) || taken.contains(&cand) || KEYWORDS.contains(&cand.as_str()) {
                continue;
            }
            taken.insert(cand.clone());
            return Some(cand);
        }
    }
    None
}

/// 主入口：把重复的数字字面量提升成局部变量。
///
/// `min_count`：出现次数阈值（用户要求「超过 2 个」，即 ≥ 3）。
/// 返回 (改造后的源码, 提升的种类数)。
pub fn hoist_repeated_numbers(src: &str, min_count: usize) -> (String, usize) {
    let toks = lex(src);
    let n = toks.len();
    if n == 0 {
        return (src.to_string(), 0);
    }
    let funcs = func_of_token(&toks);

    // function 关键字的 token 下标（用于求函数体插入点）
    let mut func_head: HashMap<usize, usize> = HashMap::new(); // func_id -> 插入点
    let mut next_id = 1usize;
    {
        let owned = owned_do_set(&toks);
        let mut stack: Vec<usize> = vec![0];
        let mut cur = 0usize;
        for i in 0..n {
            let t = &toks[i];
            if t.kind == KIND_WORD && (t.text == "end" || t.text == "until") {
                if stack.len() > 1 {
                    stack.pop();
                    cur = *stack.last().unwrap();
                }
                continue;
            }
            if t.kind == KIND_WORD {
                match t.text.as_str() {
                    "function" => {
                        let id = next_id;
                        next_id += 1;
                        if let Some(h) = body_head(&toks, i) {
                            func_head.insert(id, h);
                        }
                        stack.push(cur);
                        cur = id;
                    }
                    "if" | "for" | "while" | "repeat" => stack.push(cur),
                    "do" => {
                        if !owned.contains(&i) {
                            stack.push(cur);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // 顶层（chunk）的插入点必须在 `local f = ...` **之后**：
    // Luau 里 `...` 只在「chunk 主块的第一个语句」处是 vararg，前面插了 local 之后
    // 就变成 "cannot use '...' outside a vararg function"。而 `local f=...` 常常
    // 正是产物的第一条语句，所以一律跳到「第一条非 local 语句」之前。
    {
        let mut head = 0usize;
        let mut i = 0usize;
        while i < n {
            let t = &toks[i];
            let is_local = t.kind == KIND_WORD && t.text == "local";
            if !is_local {
                break;
            }
            // 跳过这条 local 语句：到同层的下一条语句起点
            let mut j = i + 1;
            let mut pd = 0i32;
            while j < n {
                let u = &toks[j];
                if u.kind == KIND_SYM {
                    match u.text.as_str() {
                        "(" | "[" | "{" => pd += 1,
                        ")" | "]" | "}" => pd -= 1,
                        ";" if pd == 0 => {
                            j += 1;
                            break;
                        }
                        _ => {}
                    }
                }
                let starts_new = (u.kind == KIND_WORD
                    && matches!(
                        u.text.as_str(),
                        "local" | "return" | "if" | "for" | "while" | "repeat" | "function" | "do"
                    )
                    && pd == 0
                    && j > i + 1)
                    || (u.kind == KIND_NUM && pd == 0 && j > i + 1);
                if starts_new {
                    break;
                }
                j += 1;
            }
            head = j;
            i = j;
        }
        func_head.insert(0, head);
    }

    // 统计 (函数, 值) → 出现次数 / 全部下标
    let mut sites: HashMap<(usize, i128), Vec<usize>> = HashMap::new();
    for i in 0..n {
        if toks[i].kind == KIND_NUM && is_plain_number(&toks, i) {
            if let Some(v) = parse_int(&toks[i].text) {
                sites.entry((funcs[i], v)).or_default().push(i);
            }
        }
    }

    // 全文出现过的标识符（新名字不能与它们同名）
    let mut used_words: HashSet<String> = HashSet::new();
    for t in &toks {
        if t.kind == KIND_WORD {
            used_words.insert(t.text.clone());
        }
    }

    // 选取候选：先按「能省多少」从大到小，收益相同时按 (函数, 值) 保证稳定
    let mut cands: Vec<((usize, i128), i128)> = Vec::new();
    for (&(f, v), idxs) in &sites {
        if idxs.len() < min_count {
            continue;
        }
        // 声明开销：`local `(6) + 名字 + `=`(1) + 字面量 + `;`(1)。
        // 这里按 2 字符名估算（实际常用 1 字符，只会更省）。
        let lit_len = idxs.iter().map(|&i| toks[i].text.len()).max().unwrap_or(1) as i128;
        let saved = (idxs.len() as i128 - 1) * (lit_len - 2) - (8 + 2 + lit_len);
        if saved > 0 {
            cands.push(((f, v), saved));
        }
    }
    cands.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let mut taken_names: HashSet<String> = HashSet::new();
    let mut repl: HashMap<usize, String> = HashMap::new();
    let mut decls: HashMap<usize, Vec<String>> = HashMap::new();
    let mut hoisted = 0usize;
    for ((f, _v), _gain) in cands {
        let Some(&head) = func_head.get(&f) else { continue };
        let idxs = &sites[&(f, _v)];
        // 统一用最长的那一份字面量做声明，保证替换后括号/分隔符不出现歧义
        let Some(&first) = idxs.first() else { continue };
        let lit = toks[first].text.clone();
        let Some(name) = fresh_short_name(&used_words, &mut taken_names, 1) else {
            break;
        };
        // 真正的收益核算（实际名字长度）
        let saved = (idxs.len() as i128 - 1) * (lit.len() as i128 - name.len() as i128)
            - (8 + name.len() as i128 + lit.len() as i128);
        if saved <= 0 {
            continue;
        }
        for &i in idxs {
            repl.insert(i, name.clone());
        }
        decls.entry(f).or_default().push(format!("local {}={};", name, lit));
        hoisted += 1;
        let _ = head;
    }
    if repl.is_empty() {
        return (src.to_string(), 0);
    }

    // 逐 token 回填：声明都放在对应函数体的插入点
    let mut decl_at: HashMap<usize, Vec<String>> = HashMap::new();
    for (f, list) in decls {
        if let Some(&head) = func_head.get(&f) {
            decl_at.entry(head).or_default().extend(list);
        }
    }
    let mut out = String::with_capacity(src.len());
    let mut last_end = 0usize;
    for i in 0..n {
        let t = &toks[i];
        if let Some(list) = decl_at.remove(&i) {
            out.push_str(&src[last_end..t.start]);
            out.push_str(&list.join(""));
            last_end = t.start;
        }
        if let Some(name) = repl.get(&i) {
            out.push_str(&src[last_end..t.start]);
            out.push_str(name);
            last_end = t.end;
        }
    }
    out.push_str(&src[last_end..]);
    (out, hoisted)
}

#[cfg(test)]
mod tests {
    use super::hoist_repeated_numbers;

    #[test]
    fn hoists_repeated_numbers() {
        // 11 字节字面量 ×4 次：替换成 1 字符名才划算
        let src = "local a=1;print(0B1010_1010==0B1010_1010,0B1010_1010,0B1010_1010)";
        let (out, n) = hoist_repeated_numbers(src, 3);
        assert_eq!(n, 1);
        assert!(out.contains("local "));
        assert_eq!(out.matches("0B1010_1010").count(), 1, "只应剩声明里那一份: {out}");
    }

    #[test]
    fn hoists_in_function_scope_and_keeps_index_syntax() {
        // 函数内 3 次 0x1F4（500）；`t.5` 是索引语法糖，绝不能换成变量
        let src = "local t={}\nlocal function f()\n  t.5=1\n  return 0x1F4A_3C+0x1F4A_3C+0x1F4A_3C+0x1F4A_3C+t.5\nend\nreturn f()";
        let (out, n) = hoist_repeated_numbers(src, 3);
        assert_eq!(n, 1, "{out}");
        assert!(out.contains("t.5"), "t.5 必须原样保留: {out}");
        assert_eq!(out.matches("0x1F4A_3C").count(), 1, "只留声明那一份: {out}");
        // 声明必须在函数体内、return 之前
        let decl = out.find("local ").unwrap();
        let ret = out.find("return 0x1F4A_3C").or_else(|| out.find("return ")).unwrap();
        assert!(decl < ret, "{out}");
    }

    #[test]
    fn skips_single_char_numbers() {
        let src = "print(1,1,1,1)";
        let (out, n) = hoist_repeated_numbers(src, 3);
        assert_eq!(n, 0, "1 字节的字面量换变量会变大，必须跳过: {out}");
    }
}


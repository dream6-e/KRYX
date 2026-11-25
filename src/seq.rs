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

/// 词法块（scope）编号表。
///
/// 作用域按**真正的块**划分，而不是按函数、更不是全文件：
///
/// - 函数体（`function … end`，含 `local function`）是一个块；
/// - `if … then` 的 then 分支、`else` 分支各是一个块（`elseif` 会结束前一个分支）；
/// - `do … end`、`repeat … until` 体各是一个块；
/// - `for` / `while` 循环体是一个块（声明插在循环**之前**，
///   这样循环头里的数字也能复用）。
///
/// 顶层 chunk 记 0，**不参与提升** —— 用户 2026-11-18：
/// 「不要把数字放在开头的 return 壳外，在哪个作用域复用就放在哪个作用域」。
fn block_scopes(toks: &[Tok]) -> (Vec<usize>, HashMap<usize, usize>, HashMap<usize, usize>, Vec<usize>) {
    const TOP: usize = 0;
    let n = toks.len();
    let owned = owned_do_set(toks);
    let mut scope = vec![TOP; n];
    let mut heads: HashMap<usize, usize> = HashMap::new();
    let mut parent: HashMap<usize, usize> = HashMap::new();
    // 每个块所属的「函数块」编号（顶层函数 = 0）
    let mut func_of_block: HashMap<usize, usize> = HashMap::new();
    func_of_block.insert(TOP, 0);
    let mut cur_func = 0usize;
    // (块编号, 开块关键字下标, 类型)
    let mut opened: Vec<(usize, usize, Kind)> = Vec::new();
    let mut stack: Vec<usize> = Vec::new(); // 栈里是「进入该块之前」的 scope
    let mut func_stack: Vec<usize> = Vec::new();
    let mut cur = TOP;
    let mut next_id = 1usize;

    let mut i = 0usize;
    while i < n {
        let t = &toks[i];

        // 块结束：`until` 的条件仍属于 repeat 体（能看见体内局部），
        // 这里把 `until` 本身归给体内，条件部分归外层即可（值语义不变）。
        if t.kind == KIND_WORD && (t.text == "end" || t.text == "until") {
            scope[i] = cur;
            if let Some(prev) = stack.pop() {
                cur = prev;
            }
            if t.text == "end" {
                if let Some(prev) = func_stack.pop() {
                    cur_func = prev;
                }
            }
            i += 1;
            continue;
        }

        if t.kind == KIND_WORD {
            // 结束前一个分支 / 开启新分支
            if t.text == "elseif" || t.text == "else" {
                scope[i] = cur;
                if let Some(prev) = stack.pop() {
                    cur = prev;
                }
                if t.text == "else" {
                    stack.push(cur);
                    next_id += 1;
                    let id = next_id - 1;
                    opened.push((id, i, Kind::Else));
                    parent.insert(id, cur);
                    func_of_block.insert(id, cur_func);
                    cur = id;
                }
                i += 1;
                continue;
            }
            let enter = match t.text.as_str() {
                "function" => Some(Kind::Func),
                "then" => Some(Kind::Then),
                "repeat" => Some(Kind::Repeat),
                "for" => Some(Kind::For),
                "while" => Some(Kind::While),
                "do" => {
                    if owned.contains(&i) {
                        None // `for … do` / `while … do`：块在关键字处已开
                    } else {
                        Some(Kind::Do)
                    }
                }
                _ => None,
            };
            if let Some(k) = enter {
                scope[i] = cur;
                stack.push(cur);
                next_id += 1;
                let id = next_id - 1;
                opened.push((id, i, k));
                parent.insert(id, cur);
                if k == Kind::Func {
                    func_stack.push(cur_func);
                    cur_func = id;
                }
                func_of_block.insert(id, cur_func);
                cur = id;
                i += 1;
                continue;
            }
        }

        scope[i] = cur;
        i += 1;
    }

    // 计算每个块的插入点
    for (id, kw, k) in opened {
        let head = match k {
            Kind::Func => match body_head(toks, kw) {
                Some(h) => h,
                None => continue,
            },
            // 循环：声明放在循环之前，循环头里的数字也能复用
            Kind::For | Kind::While => kw,
            // 其它：关键字之后的第一条语句
            _ => kw + 1,
        };
        if head >= n {
            continue;
        }
        // 空块（紧跟 `end` / `until` / `else` / `elseif`）没有位置可插
        if toks[head].kind == KIND_WORD
            && matches!(toks[head].text.as_str(), "end" | "until" | "else" | "elseif")
        {
            continue;
        }
        heads.insert(id, head);
    }
    // 每个 token 所属的函数块
    let mut func_of_tok = vec![0usize; n];
    for i in 0..n {
        func_of_tok[i] = *func_of_block.get(&scope[i]).unwrap_or(&0);
    }
    (scope, heads, parent, func_of_tok)
}

/// `a` 是否是 `b` 的祖先（含自身）。
fn is_ancestor(parent: &HashMap<usize, usize>, a: usize, b: usize) -> bool {
    let mut cur = b;
    loop {
        if cur == a {
            return true;
        }
        match parent.get(&cur) {
            Some(&p) => cur = p,
            None => return false,
        }
    }
}

/// 块类型
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Func,
    Then,
    Else,
    Do,
    Repeat,
    For,
    While,
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

/// 同一个块里最多放几条提升声明（避免又变成一坨 `local`）。
const MAX_DECLS_PER_BLOCK: usize = 6;

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
    // 作用域按真正的块划分（函数体 / then / else / do / repeat / for / while）。
    let (scope_of, head_of, parent_of, func_of_tok) = block_scopes(&toks);
    // 顶层 chunk 不参与提升（用户 2026-11-18）。
    const TOP: usize = 0;

    // 统计 (函数, 值) → 出现次数 / 全部下标
    // 统计粒度：**按函数**收集复用点（跨分支的复用也能被看见），
    // 但声明位置取「所有复用点的最窄公共块」——即真正复用它的那个作用域。
    let mut sites: HashMap<(usize, i128), Vec<usize>> = HashMap::new();
    for i in 0..n {
        if toks[i].kind == KIND_NUM && is_plain_number(&toks, i) {
            if let Some(v) = parse_int(&toks[i].text) {
                if scope_of[i] != TOP {
                    sites.entry((func_of_tok[i], v)).or_default().push(i);
                }
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
        let idxs = &sites[&(f, _v)];
        // 最窄公共块：所有复用点 scope 的最近公共祖先
        let mut common = scope_of[idxs[0]];
        for &i in idxs.iter().skip(1) {
            // 把 common 往上抬，直到它是 scope_of[i] 的祖先
            let mut a = common;
            let mut b = scope_of[i];
            // 先把 b 抬到与 a 同深（保持祖先关系）
            loop {
                if is_ancestor(&parent_of, a, b) {
                    break;
                }
                match parent_of.get(&a).copied() {
                    Some(p) if a != TOP => a = p,
                    _ => break,
                }
            }
            let _ = &mut b;
            common = a;
        }
        let Some(&head) = head_of.get(&common) else { continue };
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
        // 每个块的声明条数上限：否则同一个作用域里会一次堆出几十条 local，
        // 那跟「全部 local 在开头」只是位置换了一下，违背用户的本意。
        {
            let used = decls.get(&common).map(|v| v.len()).unwrap_or(0);
            if used >= MAX_DECLS_PER_BLOCK {
                continue;
            }
        }
        for &i in idxs {
            repl.insert(i, name.clone());
        }
        decls.entry(common).or_default().push(format!("local {}={};", name, lit));
        hoisted += 1;
        let _ = head;
        let _ = f;
    }
    if repl.is_empty() {
        return (src.to_string(), 0);
    }

    // 逐 token 回填：声明都放在对应函数体的插入点
    let mut decl_at: HashMap<usize, Vec<String>> = HashMap::new();
    for (f, list) in decls {
        if let Some(&head) = head_of.get(&f) {
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
        let src = "local function g()\n return 0B1010_1010+0B1010_1010+0B1010_1010+0B1010_1010\nend\nreturn g()";
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
    fn declares_inside_scope_not_at_file_head() {
        // 用户要求：数字不能一次性 local 在文件开头，要在复用它的作用域里声明。
        let src = "local a=1\nlocal function f()\n if a>0 then g(0x1F4A3C55,0x1F4A3C55,0x1F4A3C55,0x1F4A3C55) end\n return 0\nend\nreturn f()";
        let (out, n) = hoist_repeated_numbers(src, 3);
        assert_eq!(n, 1, "{out}");
        // 声明必须在 then 分支里：位于 `then` 之后、该分支的 `end` 之前
        let then_pos = out.find("then").unwrap();
        let decl = out[then_pos..].find("local ").map(|p| p + then_pos).unwrap();
        let branch_end = out[then_pos..].find("end").map(|p| p + then_pos).unwrap();
        assert!(decl > then_pos && decl < branch_end, "声明必须在 then 作用域内: {out}");
        // 不应出现「文件开头多出一条新声明」的形态：第一条语句必须还是原来的 `local a=1`
        assert!(out.starts_with("local a=1"), "不能在文件开头堆声明: {out}");
    }

    #[test]
    fn skips_single_char_numbers() {
        let src = "print(1,1,1,1)";
        let (out, n) = hoist_repeated_numbers(src, 3);
        assert_eq!(n, 0, "1 字节的字面量换变量会变大，必须跳过: {out}");
    }
}



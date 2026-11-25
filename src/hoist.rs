// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 常量提升：同一作用域里反复出现的 `nil` / `getgenv` 抽成局部变量。
//!
//! 用户 2026-11-18 的优化要求：
//! > 把 nil 和 getgenv 在这个作用域开头定义，都用变量，而不是这样写上十几遍
//!
//! 实现要点（纯文本层，跑在 `RadixSieve` 之后、`hoist_repeated_numbers` 之前）：
//!
//! 1. 用 `Reshape::Lexer::lex` 切词，天然跳过字符串 / 长字符串 / 注释；
//! 2. 以**块**为单位（函数体 / then / else / do / repeat / for / while）统计，
//!    复用 `seq::block_scopes` 的作用域划分；
//! 3. 只处理**纯标识符**文本：`nil` 与 `getgenv`。二者的语义都等同于「读一个
//!    从不被赋值的名字」，换成 `local 名字 = nil` / `local 名字 = getgenv` 之后
//!    每次读取都返回同一个值，语义严格不变；
//! 4. 声明插在「所有复用点的最窄公共块」开头 —— 也就是用户说的「这个作用域开头」，
//!    不会全部堆到文件最前面；
//! 5. 只有当「省下的字节 > 声明开销」时才提升，否则纯属增大体积。
//!
//! 语义安全（为什么 `nil` 可以换变量）：
//! - 项目产物里不存在 `nil = ...` 这种赋值（`nil` 是保留字，语法上不允许）；
//! - `local X = nil` 之后，`X` 在块内任何位置读取都是 nil，
//!   与直接写 `nil` 完全等价，包括 `x == nil` / `x ~= nil` / `return nil`；
//! - 声明点之前不会出现 `X`（`X` 是全文唯一的短名），不存在「用到未声明的 X」。
//!
//! `getgenv` 同理：它在产物里从不被赋值，只在 `getgenv and ...` / `getgenv()`
//! 两种位置被读取。

use std::collections::{HashMap, HashSet};

use crate::VM::Reshape::Lexer::{lex, Tok, KIND_WORD};

/// 可提升的纯标识符常量。
const HOISTABLE: [&str; 2] = ["nil", "getgenv"];

/// 同一个块里最多放几条常量声明。`nil` + `getgenv` 天然只有 2 条，
/// 这里留一点余量以便日后扩充。
const MAX_DECLS_PER_BLOCK: usize = 3;

/// 主入口：把同一作用域里重复的 `nil` / `getgenv` 提升成局部变量。
///
/// `min_count`：一个块内出现的次数阈值；低于它不提升（改名不划算）。
/// 返回 (改造后的源码, 提升的种类数)。
pub fn hoist_constants(src: &str, min_count: usize) -> (String, usize) {
    let toks = lex(src);
    let n = toks.len();
    if n == 0 {
        return (src.to_string(), 0);
    }
    let (scope_of, head_of, parent_of, func_of_tok) = crate::seq::block_scopes(&toks);
    /// 顶层 chunk 不参与提升（与 seq::hoist_repeated_numbers 的约定一致：
    /// 声明要落在真正复用的那个作用域里，而不是文件最前面）。
    const TOP: usize = 0;

    // 全文出现过的标识符（新名字不能与它们同名）
    let mut used_words: HashSet<String> = HashSet::new();
    for t in &toks {
        if t.kind == KIND_WORD {
            used_words.insert(t.text.clone());
        }
    }

    // 每个常量在**每个块**里的出现次数：每个复用点沿祖先链向上累加。
    // 这样「哪个块覆盖的复用点最多、又最靠近复用点」可以一次性算出来。
    let mut per_block: HashMap<(&'static str, usize), usize> = HashMap::new();
    let mut all_sites: HashMap<&'static str, Vec<usize>> = HashMap::new();
    for i in 0..n {
        if toks[i].kind != KIND_WORD || scope_of[i] == TOP {
            continue;
        }
        let Some(&which) = HOISTABLE.iter().find(|&&w| w == toks[i].text) else {
            continue;
        };
        all_sites.entry(which).or_default().push(i);
        let mut b = scope_of[i];
        loop {
            *per_block.entry((which, b)).or_insert(0) += 1;
            if b == TOP {
                break;
            }
            match parent_of.get(&b).copied() {
                Some(p) => b = p,
                None => break,
            }
        }
    }

    // 块深度：越深越贴近复用点
    let depth_of = |mut b: usize| -> usize {
        let mut d = 0usize;
        while let Some(&p) = parent_of.get(&b) {
            if b == TOP {
                break;
            }
            b = p;
            d += 1;
        }
        d
    };

    let mut taken_names: HashSet<String> = HashSet::new();
    let mut repl: HashMap<usize, String> = HashMap::new();
    let mut decls: HashMap<usize, Vec<String>> = HashMap::new();
    let mut hoisted = 0usize;

    // 贪心：每轮挑「覆盖次数最多、深度最大」的 (常量, 块) 组合，应用到划算为止。
    // 用掉一部分复用点后，剩下的可能在别的块里还能再凑一批，所以循环到不再变化。
    loop {
        let mut best: Option<((&'static str, usize), usize, usize, usize)> = None; // (key, 覆盖数, 深度, 待替换数)
        for (&(word, block), &cnt) in &per_block {
            if block == TOP {
                continue;
            }
            let sites = match all_sites.get(word) {
                Some(v) => v,
                None => continue,
            };
            // 该块内、尚未被替换的点
            let pending: Vec<usize> = sites
                .iter()
                .copied()
                .filter(|&i| !repl.contains_key(&i) && crate::seq::is_ancestor(&parent_of, block, scope_of[i]))
                .collect();
            if pending.len() < min_count {
                continue;
            }
            let d = depth_of(block);
            let cand = ((word, block), cnt, d, pending.len());
            best = match best {
                None => Some(cand),
                Some(b) => {
                    if (cand.3, cand.2) > (b.3, b.2) {
                        Some(cand)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        let Some(((word, block), _cnt, _d, _pending_n)) = best else { break };
        let sites = &all_sites[word];
        let pending: Vec<usize> = sites
            .iter()
            .copied()
            .filter(|&i| !repl.contains_key(&i) && crate::seq::is_ancestor(&parent_of, block, scope_of[i]))
            .collect();
        let Some(_head) = head_of.get(&block) else { break };
        {
            let used = decls.get(&block).map(|v| v.len()).unwrap_or(0);
            if used >= MAX_DECLS_PER_BLOCK {
                break;
            }
        }
        let Some(name) = crate::seq::fresh_short_name(&used_words, &mut taken_names, 1) else {
            break;
        };
        // 收益核算：每次出现省 (len(word) - len(name))，
        // 声明开销 `local ` (6) + name + `=` (1) + word + `;` (1)。
        let saved = (pending.len() as i128) * (word.len() as i128 - name.len() as i128)
            - (8 + name.len() as i128 + word.len() as i128);
        if saved <= 0 {
            break;
        }
        for &i in &pending {
            repl.insert(i, name.clone());
        }
        decls
            .entry(block)
            .or_default()
            .push(format!("local {}={};", name, word));
        hoisted += 1;
    }

    if repl.is_empty() {
        return (src.to_string(), 0);
    }

    // 逐 token 回填：声明插在对应块的插入点
    let mut decl_at: HashMap<usize, Vec<String>> = HashMap::new();
    for (block, list) in decls {
        if let Some(&head) = head_of.get(&block) {
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
    use super::hoist_constants;

    #[test]
    fn hoists_getgenv_across_if_branches() {
        // getgenv 7 字节，6 次才划算（声明本身 ~17 字节）
        let src = "local function f()\n local a=1\n if a>0 then if getgenv then a=1 end end\n if a>1 then if getgenv then a=2 end end\n if a>2 then if getgenv then a=3 end end\n if a>3 then if getgenv then a=4 end end\n if a>4 then if getgenv then a=5 end end\n return a\nend\nreturn f()";
        let (out, n) = hoist_constants(src, 3);
        assert_eq!(n, 1, "{out}");
        assert_eq!(out.matches("getgenv").count(), 1, "只应剩声明里那一份: {out}");
        assert!(out.contains("=getgenv;"), "{out}");
    }

    #[test]
    fn hoists_nil_when_enough_occurrences() {
        // nil 只有 3 字节，要 9 次以上才划算
        let mut body = String::new();
        for _ in 0..9 {
            body.push_str(" local x=a==nil and nil or 1\n");
        }
        let src = format!("local function f()\n local a=1\n{body} return a\nend\nreturn f()");
        let (out, n) = hoist_constants(&src, 3);
        assert_eq!(n, 1, "{out}");
        assert!(out.contains("=nil;"), "{out}");
        // 声明那一份 + 替换后均为短名，原文 nil 只剩 1 次
        assert_eq!(out.matches("nil").count(), 1, "{out}");
    }

    #[test]
    fn does_not_touch_strings_or_long_brackets() {
        let mut body = String::new();
        for _ in 0..8 {
            body.push_str(" local x=getgenv and 1 or 2\n");
        }
        let src = format!(
            "local function f()\n local a=[[getgenv getgenv getgenv]]\n local b=\"getgenv getgenv\"\n{body} return a~=nil and b~=nil or a\nend\nreturn f()"
        );
        let (out, n) = hoist_constants(&src, 3);
        assert_eq!(n, 1, "{out}");
        // 字符串与长括号里的内容必须原样保留
        assert!(out.contains("[[getgenv getgenv getgenv]]"), "{out}");
        assert!(out.contains("\"getgenv getgenv\""), "{out}");
        // 全文件计数 = 长括号 3 + 短字符串 2 + 声明 1 = 6；代码区只剩声明那一份
        assert_eq!(out.matches("getgenv").count(), 6, "{out}");
    }

    #[test]
    fn skips_when_not_worth_it() {
        let src = "local function f() return nil,nil end return f()";
        let (out, n) = hoist_constants(src, 3);
        assert_eq!(n, 0, "{out}");
        assert_eq!(out, src);
    }

    #[test]
    fn declares_inside_scope_not_at_file_head() {
        let mut body = String::new();
        for _ in 0..8 {
            body.push_str("  if a>0 then if getgenv then a=1 end end\n");
        }
        let src = format!(
            "local a=1\nlocal function f()\n{body} return a\nend\nreturn f()"
        );
        let (out, n) = hoist_constants(&src, 3);
        assert_eq!(n, 1, "{out}");
        assert!(out.starts_with("local a=1"), "不能在文件开头堆声明: {out}");
        // 声明必须在 f 的函数体内
        let fpos = out.find("local function f()").unwrap();
        let decl = out[fpos..].find("=getgenv;").map(|p| p + fpos).unwrap();
        assert!(decl > fpos, "{out}");
    }
}

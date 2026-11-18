// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 标识符登记表 + 收尾重命名。
//!
//! sample2 的全部标识符都是 1~2 个字符（`v,u,m,f,K,p,h,J,Z,b,j,H,C,U,Y,z,n,S,w,a` …），
//! 而生成器为了稳妥一直用 7~13 字符的长名字。这里做两件事：
//!
//! 1. `register`：任何生成器（`GenRng` / `OpcodesRng` / `AntiTamper` / `NamePool`）
//!    造出一个新名字时登记到线程本地集合里。
//! 2. `shrink`：成品文本完成后，把所有**已登记**的标识符统一换成 1~2 字符短名，
//!    并避开文本里所有**未登记**的标识符（模板里的 `execute` / `chunk` / `env` /
//!    `op` / `inst_A` / `getgenv` / `a_` / `b_` … 这些固定名一律不碰）。
//!
//! 只按 token 位置替换，跳过字符串/长括号/数字，因此不会误伤字符串内容，
//! 也不会破坏 token 之间的分隔符。替换是**单射**的（不同老名 → 不同新名），
//! 所以语义严格不变。

use std::cell::RefCell;
use std::collections::HashSet;

thread_local! {
    static REGISTRY: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

pub fn reset() {
    REGISTRY.with(|r| r.borrow_mut().clear());
}

pub fn register(name: &str) {
    if name.is_empty() {
        return;
    }
    REGISTRY.with(|r| {
        r.borrow_mut().insert(name.to_string());
    });
}

pub fn registered(name: &str) -> bool {
    REGISTRY.with(|r| r.borrow().contains(name))
}

fn is_word_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn skip_string(b: &[u8], start: usize) -> usize {
    let n = b.len();
    let q = b[start];
    let mut i = start + 1;
    while i < n {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == q {
            return i + 1;
        }
        i += 1;
    }
    n
}

fn skip_long(b: &[u8], src: &str, start: usize) -> Option<usize> {
    if b[start] != b'[' {
        return None;
    }
    let n = b.len();
    let mut j = start + 1;
    while j < n && b[j] == b'=' {
        j += 1;
    }
    if j >= n || b[j] != b'[' {
        return None;
    }
    let close = format!("]{}]", "=".repeat(j - start - 1));
    match src[j + 1..].find(&close) {
        Some(p) => Some(j + 1 + p + close.len()),
        None => Some(n),
    }
}

/// 收集文本中所有标识符（按 token 位置）
fn scan_identifiers(src: &str) -> Vec<(usize, usize, String)> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            i = skip_string(b, i);
            continue;
        }
        if c == b'[' {
            if let Some(j) = skip_long(b, src, i) {
                i = j;
                continue;
            }
        }
        if c.is_ascii_digit() {
            let mut j = i;
            if c == b'0' && i + 1 < n && (b[i + 1] == b'x' || b[i + 1] == b'X') {
                j = i + 2;
                while j < n && (b[j].is_ascii_hexdigit() || b[j] == b'_') {
                    j += 1;
                }
            } else if c == b'0' && i + 1 < n && (b[i + 1] == b'b' || b[i + 1] == b'B') {
                j = i + 2;
                while j < n && (b[j] == b'0' || b[j] == b'1' || b[j] == b'_') {
                    j += 1;
                }
            } else {
                while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'.' || b[j] == b'_') {
                    j += 1;
                }
            }
            i = j;
            continue;
        }
        if is_word_start(c) {
            let mut j = i;
            while j < n && is_word_char(b[j]) {
                j += 1;
            }
            out.push((i, j, src[i..j].to_string()));
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// 1~2 字符候选名池：先用 52 个字母，再退到 `_`/数字组合。
/// 单字母只有 52 个，超过之后自然变成两字符（`ab`、`cK`、`_7` …），
/// 与 sample2「1~2 字符随机标识符」的分布一致。
fn candidate(i: usize) -> String {
    const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    const TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
    let h = HEAD.len();
    let t = TAIL.len();
    if i < h {
        return (HEAD[i] as char).to_string();
    }
    let k = i - h;
    let a = k / t;
    let bb = k % t;
    if a >= h {
        // 极端情况（>3300 个名字）：退化成三字符
        let k2 = k - h * t;
        let a1 = k2 / (t * t);
        let a2 = (k2 / t) % t;
        let a3 = k2 % t;
        return format!(
            "{}{}{}",
            HEAD[a1 % h] as char, TAIL[a2] as char, TAIL[a3] as char
        );
    }
    format!("{}{}", HEAD[a] as char, TAIL[bb] as char)
}

/// 取一个还没被任何登记名占用的单字母短名（用于入口 `J` 这类必须一眼可见的名字）。
pub fn short_single(src: &str, rng: &mut crate::VM::VM_Backend::Generator::GenRng) -> String {
    const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let names = REGISTRY.with(|r| r.borrow().clone());
    let idents = scan_identifiers(src);
    let mut used: HashSet<&str> = HashSet::new();
    for (_, _, t) in &idents {
        used.insert(t.as_str());
    }
    loop {
        let c = HEAD[rng.range(0, HEAD.len())] as char;
        let cand = c.to_string();
        let clash = used.contains(cand.as_str())
            || names.contains(&cand)
            || matches!(cand.as_str(), "and" | "or" | "if" | "do" | "in" | "end" | "nil" | "not");
        if !clash {
            return cand;
        }
    }
}

/// 把已登记的标识符统一压缩成 1~2 字符短名。
/// - 文本中未登记的标识符视为「固定名」，绝不复用
/// - 映射保持单射，语义不变
pub fn shrink(src: &str) -> String {
    let names = REGISTRY.with(|r| r.borrow().clone());
    if names.is_empty() {
        return src.to_string();
    }
    let idents = scan_identifiers(src);
    // 固定名 = 文本里出现但没有登记过的标识符
    let mut fixed: HashSet<&str> = HashSet::new();
    for (_, _, t) in &idents {
        if !names.contains(t) {
            fixed.insert(t.as_str());
        }
    }
    // 老名 → 新名（按出现顺序，稳定）
    let mut seen: Vec<String> = Vec::new();
    let mut seen_set: HashSet<&str> = HashSet::new();
    for (_, _, t) in &idents {
        if names.contains(t) && !seen_set.contains(t.as_str()) {
            seen_set.insert(t.as_str());
            seen.push(t.clone());
        }
    }
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut taken: HashSet<String> = HashSet::new();
    let mut cursor = 0usize;
    for old in &seen {
        loop {
            let cand = candidate(cursor);
            cursor += 1;
            if fixed.contains(cand.as_str()) || taken.contains(&cand) {
                continue;
            }
            if matches!(
                cand.as_str(),
                "and" | "or" | "if" | "do" | "in" | "end" | "nil" | "not" | "for" | "local"
            ) {
                continue;
            }
            taken.insert(cand.clone());
            map.insert(old.clone(), cand);
            break;
        }
    }
    let mut out = String::with_capacity(src.len());
    let mut last = 0usize;
    for (s, e, t) in idents {
        if let Some(nn) = map.get(&t) {
            out.push_str(&src[last..s]);
            out.push_str(nn);
            last = e;
        }
    }
    out.push_str(&src[last..]);
    out
}

/// 把 `}):X()(...)` 里的入口名字换成独占的单字母（sample2 的 `:J()`）。
/// 只在整段文本里该单字母未被占用时生效，保证不产生同名冲突。
/// 标记：是否已经把标识符压过一遍（避免第二次 shrink 把 `u` 这类短名当老名）
thread_local! {
    static ALREADY: RefCell<bool> = RefCell::new(false);
}

pub fn shrink_once(src: &str) -> String {
    let done = ALREADY.with(|d| *d.borrow());
    if done {
        return src.to_string();
    }
    ALREADY.with(|d| *d.borrow_mut() = true);
    shrink(src)
}

pub fn promote_entry(src: &str) -> String {
    let tail_pat = "()(...)";
    let Some(pos) = src.rfind(tail_pat) else { return src.to_string() };
    // 往回找 `):`
    let Some(colon) = src[..pos].rfind("):") else { return src.to_string() };
    let name_start = colon + 2;
    let name: String = src[name_start..pos].to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return src.to_string();
    }
    let idents = scan_identifiers(src);
    let mut used: HashSet<&str> = HashSet::new();
    for (_, _, t) in &idents {
        used.insert(t.as_str());
    }
    const ORDER: &[u8] = b"JjMmnNqQxXyYwWzZrRsStTuUkKlLiIoOpPaAbBcCdDeEfFgGhHvV";
    for c in ORDER {
        let cand = (*c as char).to_string();
        if cand == name || used.contains(cand.as_str()) {
            continue;
        }
        if matches!(cand.as_str(), "and" | "or" | "if" | "do" | "in" | "end" | "nil" | "not") {
            continue;
        }
        // 全部替换（表字段定义 + 调用点）
        return replace_ident(src, &name, &cand);
    }
    src.to_string()
}

fn replace_ident(src: &str, old: &str, new: &str) -> String {
    let idents = scan_identifiers(src);
    let mut out = String::with_capacity(src.len());
    let mut last = 0usize;
    for (s, e, t) in idents {
        if t == old {
            out.push_str(&src[last..s]);
            out.push_str(new);
            last = e;
        }
    }
    out.push_str(&src[last..]);
    out
}

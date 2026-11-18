// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! sample2 形态整形用到的词法器：把 Lua/Luau 源码切成带**块深度**和
//! **原始起止偏移**的 token。深度用来找 depth-0 语句边界，偏移用来原样回填
//! 源切片（保证换行/空格不被破坏）。

use crate::VM::VM_Backend::Generator::GenRng;
use std::collections::{HashMap, HashSet};

pub const KIND_WORD: u8 = 0;
pub const KIND_NUM: u8 = 1;
pub const KIND_STR: u8 = 2;
pub const KIND_SYM: u8 = 3;

#[derive(Clone)]
pub struct Tok {
    pub text: String,
    pub kind: u8,
    pub depth: i32,
    pub start: usize,
    pub end: usize,
}

pub(crate) fn is_word_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}
pub(crate) fn is_word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

pub(crate) fn lex(src: &str) -> Vec<Tok> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out: Vec<Tok> = Vec::new();
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'-' && i + 1 < n && b[i + 1] == b'-' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        if c == b'"' || c == b'\'' {
            i += 1;
            while i < n {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(Tok { text: src[start..i.min(n)].to_string(), kind: KIND_STR, depth: 0, start, end: i.min(n) });
            continue;
        }
        if c == b'[' {
            let mut j = i + 1;
            while j < n && b[j] == b'=' {
                j += 1;
            }
            if j < n && b[j] == b'[' {
                let close = format!("]{}]", "=".repeat(j - i - 1));
                let stop = match src[j + 1..].find(&close) {
                    Some(p) => j + 1 + p + close.len(),
                    None => n,
                };
                out.push(Tok { text: src[start..stop].to_string(), kind: KIND_STR, depth: 0, start, end: stop });
                i = stop;
                continue;
            }
        }
        if is_word_start(c) {
            let mut j = i;
            while j < n && is_word_char(b[j]) {
                j += 1;
            }
            out.push(Tok { text: src[i..j].to_string(), kind: KIND_WORD, depth: 0, start: i, end: j });
            i = j;
            continue;
        }
        if c.is_ascii_digit() || (c == b'.' && i + 1 < n && b[i + 1].is_ascii_digit()) {
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
            out.push(Tok { text: src[i..j].to_string(), kind: KIND_NUM, depth: 0, start: i, end: j });
            i = j;
            continue;
        }
        let mut len = 1usize;
        if i + 2 < n && &src[i..i + 3] == "..." {
            len = 3;
        } else if i + 1 < n {
            let two = &src[i..i + 2];
            if matches!(two, "==" | "~=" | "<=" | ">=" | ".." | "::") {
                len = 2;
            }
        }
        out.push(Tok { text: src[i..i + len].to_string(), kind: KIND_SYM, depth: 0, start: i, end: i + len });
        i += len;
    }
    // 块深度：`for … do` / `while … do` 的 `do` 不计层，其余 `do … end` 计一层。
    // 先把「属于 for/while 的 do」标出来（向后找括号配平后的第一个 `do`）。
    let m = out.len();
    let mut owned_do: HashSet<usize> = HashSet::new();
    for i in 0..m {
        if out[i].kind == KIND_WORD && (out[i].text == "for" || out[i].text == "while") {
            let mut p = i + 1;
            let mut pd = 0i32;
            while p < m {
                let t = &out[p];
                if t.kind == KIND_SYM {
                    match t.text.as_str() {
                        "(" | "[" | "{" => pd += 1,
                        ")" | "]" | "}" => pd -= 1,
                        _ => {}
                    }
                }
                if t.kind == KIND_WORD && t.text == "do" && pd <= 0 {
                    owned_do.insert(p);
                    break;
                }
                p += 1;
            }
        }
    }
    let mut depth = 0i32;
    for (i, t) in out.iter_mut().enumerate() {
        t.depth = depth;
        if t.kind == KIND_WORD {
            match t.text.as_str() {
                "function" | "if" | "for" | "while" | "repeat" => depth += 1,
                "do" => {
                    if !owned_do.contains(&i) {
                        depth += 1;
                    }
                }
                "end" | "until" => depth -= 1,
                _ => {}
            }
        }
    }
    out
}

pub(crate) fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "and" | "break" | "do" | "else" | "elseif" | "end" | "false" | "for" | "function" | "if"
            | "in" | "local" | "nil" | "not" | "or" | "repeat" | "return" | "then" | "true"
            | "until" | "while"
    )
}

/// sample2 风格的密数键字面量（十六进制/二进制/十进制混用，随机 `_` 与大小写前缀）
pub(crate) fn key_lit(rng: &mut GenRng, used: &mut HashSet<u32>) -> String {
    let mut v = rng.range(1, 60000) as u32;
    while used.contains(&v) {
        v = v.wrapping_add(1);
        if v == 0 {
            v = 1;
        }
    }
    used.insert(v);
    match rng.range(0, 3) {
        0 => {
            let s = format!("{:X}", v);
            let s = if rng.range(0, 2) == 0 {
                format!("{}{}", "0".repeat(rng.range(1, 3)), s)
            } else {
                s
            };
            let s = maybe_us(&s, rng);
            if rng.range(0, 2) == 0 {
                format!("0X{}", s)
            } else {
                format!("0x{}", s)
            }
        }
        1 => {
            let s = maybe_us(&format!("{:b}", v), rng);
            if rng.range(0, 2) == 0 {
                format!("0B{}", s)
            } else {
                format!("0b{}", s)
            }
        }
        _ => format!("{}", v),
    }
}

pub(crate) fn maybe_us(s: &str, rng: &mut GenRng) -> String {
    if s.len() < 4 || rng.range(0, 10) < 5 {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut mark: HashSet<usize> = HashSet::new();
    for _ in 0..rng.range(1, 3) {
        mark.insert(1 + rng.range(0, chars.len() - 1));
    }
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if mark.contains(&i) {
            out.push('_');
        }
        out.push(*c);
    }
    out
}

/// 密数键也可以做成 `q` 表那样的常量（sample2 有 `v.q[…]` 用法），这里偶尔用
/// `u[0x..]` 与 `u[键字面量]` 两种写法交替，保持外观不一。
pub struct Slots {
    map: HashMap<String, String>,
    used_nums: HashSet<u32>,
}

impl Slots {
    pub fn new() -> Self {
        Self { map: HashMap::new(), used_nums: HashSet::new() }
    }
    pub fn key_for(&mut self, name: &str, rng: &mut GenRng) -> String {
        if let Some(k) = self.map.get(name) {
            return k.clone();
        }
        let k = key_lit(rng, &mut self.used_nums);
        self.map.insert(name.to_string(), k.clone());
        k
    }
}

pub struct Stats {
    pub slots: usize,
    pub methods: usize,
}

struct Body {
    toks: Vec<Tok>,
}

/// depth 0 的语句边界（以 `local`/`return` 等关键字或前一条 `end` 结束为界）
pub fn stmt_bounds(toks: &[Tok]) -> Vec<(usize, usize)> {
    let n = toks.len();
    let mut bounds = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < n {
        if toks[i].kind == KIND_SYM && toks[i].text == ";" && toks[i].depth == 0 {
            if start < i {
                bounds.push((start, i));
            }
            start = i + 1;
        }
        i += 1;
    }
    if start < n {
        bounds.push((start, n));
    }
    bounds
}

/// 原样回填用：Tok 里已经带了原始起止偏移，这里不需要（BODY 直接从源切片输出）。
pub fn render(toks: &[Tok]) -> String {
    let mut out = String::new();
    for (i, t) in toks.iter().enumerate() {
        out.push_str(&t.text);
        if i + 1 < toks.len() && need_space(t, &toks[i + 1]) {
            out.push(' ');
        }
    }
    out
}

pub fn need_space(a: &Tok, b: &Tok) -> bool {
    let aw = a.kind == KIND_WORD || a.kind == KIND_NUM;
    let bw = b.kind == KIND_WORD || b.kind == KIND_NUM;
    if aw && bw {
        return true;
    }
    if a.kind == KIND_NUM && b.text.starts_with('.') {
        return true;
    }
    if a.text == "-" && b.text == "-" {
        return true;
    }
    if a.text.ends_with('.') && b.text.starts_with('.') {
        return true;
    }
    false
}


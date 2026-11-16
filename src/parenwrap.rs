// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 产物写盘前的收尾变换：
//! 1. `x[数字]`（x 为任意字母/下划线开头的标识符）约 70% 改写为 `(x)[数字]`；
//! 2. 独立的空表 `{}` 全部改写为 `({})`；
//! 3. 十六进制数字字面量：字母大小写随机（含 `x` 前缀），70% 概率插入 1~2 个
//!    随机位置的 `_`（单个数字最多 2 个，含原有 `_`）。
//! 只作用于真实代码区域；字符串（含长字符串）、注释（含长注释）原样跳过，
//! 避免损坏载荷密文。多字节字符按字节边界整段拷贝，不会被截断。
use rand::Rng;

#[inline]
fn is_ident_start(b: u8) -> bool { b.is_ascii_alphabetic() || b == b'_' }
#[inline]
fn is_ident_char(b: u8) -> bool { b.is_ascii_alphanumeric() || b == b'_' }

/// 关键字不是前缀表达式，其后接 `(x)` 不会被解析成调用
fn is_lua_keyword(tok: &[u8]) -> bool {
    matches!(tok,
        b"and" | b"or" | b"not" | b"if" | b"elseif" | b"else" | b"then" | b"do" | b"end"
        | b"while" | b"repeat" | b"until" | b"for" | b"in" | b"local" | b"return"
        | b"break" | b"continue" | b"goto" | b"function")
}

/// 把十六进制字面量整体改写为：前缀 `0x`/`0X` 大小写随机 + 十六进制字母大小写随机（数字不变），
/// 并在 70% 概率下插入 1~2 个随机位置的 `_`（含原有 `_`，单个数字总数不超过 2 个）。
/// Luau 词法分析前会先剥离数字里的全部 `_`，因此插入任意位置都合法。
/// 输入 `bytes[i] == '0'` 且 `bytes[i+1]` 为 `x`/`X`，且后续至少有 1 个十六进制数字/`_`。
fn transform_hex_literal(code: &str, i: usize, rng: &mut rand::rngs::ThreadRng) -> String {
    let bytes = code.as_bytes();
    let len = bytes.len();
    let mut end = i + 2;
    while end < len && (bytes[end].is_ascii_hexdigit() || bytes[end] == b'_') { end += 1; }
    let body = &code[i + 2..end];

    // 1) 大小写随机
    let mut out = String::with_capacity(end - i + 2);
    out.push('0');
    out.push(if rng.random_bool(0.5) { 'x' } else { 'X' });
    let mut body_buf = String::with_capacity(end - i);
    for c in body.chars() {
        if c.is_ascii_alphabetic() {
            let lower = c.to_ascii_lowercase();
            body_buf.push(if rng.random_bool(0.5) { lower } else { lower.to_ascii_uppercase() });
        } else {
            body_buf.push(c); // 数字与原有 '_' 原样保留
        }
    }

    // 2) 70% 概率插入 1~2 个 '_'；单个数字最多 2 个（含原有的）
    let existing_us = body.chars().filter(|&c| c == '_').count();
    let cap = 2usize.saturating_sub(existing_us);
    if cap > 0 && rng.random_bool(0.7) {
        let add = if cap == 1 { 1 } else { rng.random_range(1..=2usize) };
        // 候选间隙 0..=body_buf.len()（0=前缀与首个字符之间，len=末尾）
        let gaps_len = body_buf.chars().count();
        let mut gaps: Vec<usize> = (0..=gaps_len).collect();
        let mut chosen: Vec<usize> = Vec::with_capacity(add);
        for _ in 0..add {
            if gaps.is_empty() { break; }
            let idx = rng.random_range(0..gaps.len());
            chosen.push(gaps.swap_remove(idx));
        }
        let mut buf = String::with_capacity(body_buf.len() + chosen.len());
        for (k, c) in body_buf.chars().enumerate() {
            if chosen.contains(&k) { buf.push('_'); }
            buf.push(c);
        }
        if chosen.contains(&gaps_len) { buf.push('_'); }
        body_buf = buf;
    }

    out.push_str(&body_buf);
    out
}

/// 若字节 i 之前（跳过空白）是「前缀表达式的结尾」，则其后不能再接 `(x)`（会被当作调用，
/// 与中间空白无关），该位置不允许包裹。以下前驱都会把包裹后的形式变成函数调用或非法续接：
///   '.' 成员访问 / ':' 方法名 / 标识符或数字字符（边界）/ ')' ']' '}' 引号
/// 唯一例外：'..'（连接符，安全），以及关键字（不是前缀表达式）。
fn prev_blocks_wrap(bytes: &[u8], i: usize) -> bool {
    let mut j = i;
    while j > 0 {
        let p = bytes[j - 1];
        if p == b' ' || p == b'\t' || p == b'\n' || p == b'\r' { j -= 1; continue; }
        return match p {
            b'.' => !(j >= 2 && bytes[j - 2] == b'.'),
            b':' | b')' | b']' | b'}' | b'"' | b'\'' => true,
            _ if is_ident_char(p) => {
                let mut k = j;
                while k > 0 && is_ident_char(bytes[k - 1]) { k -= 1; }
                !is_lua_keyword(&bytes[k..j])
            }
            _ => false,
        };
    }
    false
}

/// 若 bytes[i] 处开始一个长括号 `[` `=`* n `[`（如 `[==[`），返回 n（= 的个数）
fn long_bracket_open(bytes: &[u8], i: usize) -> Option<usize> {
    if i >= bytes.len() || bytes[i] != b'[' { return None; }
    let mut j = i + 1;
    let mut level = 0usize;
    while j < bytes.len() && bytes[j] == b'=' { level += 1; j += 1; }
    if j < bytes.len() && bytes[j] == b'[' { Some(level) } else { None }
}

/// 从长括号开始处查找对应的 `]` `=`* level `]`，返回其后一位（找不到则返回 len）
fn long_bracket_close(bytes: &[u8], open_at: usize, level: usize) -> usize {
    let mut j = open_at + 1 + level + 1;
    while j < bytes.len() {
        if bytes[j] == b']' {
            let mut k = j + 1;
            let mut eq = 0usize;
            while k < bytes.len() && bytes[k] == b'=' { eq += 1; k += 1; }
            if eq == level && k < bytes.len() && bytes[k] == b']' {
                return k + 1;
            }
        }
        j += 1;
    }
    bytes.len()
}

fn flush(out: &mut String, code: &str, last: usize, upto: usize) {
    if upto > last { out.push_str(&code[last..upto]); }
}

pub fn wrap_misc(code: &str) -> String {
    let bytes = code.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 64 + 32);
    let mut last = 0usize;
    let mut i = 0usize;
    let mut rng = rand::thread_rng();

    while i < len {
        let b = bytes[i];

        // 注释：-- 直到行尾；--[=*[ ... ]=*] 长注释
        if b == b'-' && i + 1 < len && bytes[i + 1] == b'-' {
            if let Some(level) = long_bracket_open(bytes, i + 2) {
                let end = long_bracket_close(bytes, i + 2, level);
                flush(&mut out, code, last, end);
                i = end; last = end; continue;
            }
            let mut j = i + 2;
            while j < len && bytes[j] != b'\n' { j += 1; }
            flush(&mut out, code, last, j);
            i = j; last = j; continue;
        }

        // 长字符串 [=*[ ... ]=*]（载荷密文在此整体跳过）
        if let Some(level) = long_bracket_open(bytes, i) {
            let end = long_bracket_close(bytes, i, level);
            flush(&mut out, code, last, end);
            i = end; last = end; continue;
        }

        // 短字符串 '...' / "..."（支持反斜杠转义）
        if b == b'"' || b == b'\'' {
            let mut j = i + 1;
            while j < len {
                let c = bytes[j];
                if c == b'\\' { j = (j + 2).min(len); continue; }
                if c == b { j += 1; break; }
                if c == b'\n' { break; }
                j += 1;
            }
            flush(&mut out, code, last, j);
            i = j; last = j; continue;
        }

        // 十六进制数字 0x..：字母大小写随机；70% 概率插入 1~2 个 '_'
        if b == b'0' && i + 1 < len && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let mut end = i + 2;
            while end < len && (bytes[end].is_ascii_hexdigit() || bytes[end] == b'_') { end += 1; }
            if end > i + 2 {
                flush(&mut out, code, last, i);
                out.push_str(&transform_hex_literal(code, i, &mut rng));
                i = end; last = end; continue;
            }
        }

        // 空表 {} -> ({})
        if b == b'{' && i + 1 < len && bytes[i + 1] == b'}' {
            flush(&mut out, code, last, i);
            out.push_str("({})");
            i += 2; last = i; continue;
        }

        // x[数字] -> (x)[数字]（约 70% 概率）
        // 标识符整体先作为一个 token 跳过，避免回扫进标识符内部把片段当成新标识符；
        // 标识符前驱若是「前缀结尾」（见 prev_blocks_wrap），包裹后会被解析成函数调用，跳过
        if is_ident_start(b) {
            let mut j = i;
            while j < len && is_ident_char(bytes[j]) { j += 1; }
            if !prev_blocks_wrap(bytes, i) && j < len && bytes[j] == b'[' {
                // 括号内必须是一个合法的数字字面量（-? 0x.. / 0b.. / 十进制，可含 _ 和指数），
                // 不能是其它标识符或表达式，否则会把非数字索引用括号包起来破坏语法
                let mut k = j + 1;
                if k < len && bytes[k] == b'-' { k += 1; }
                let body = k;
                let mut is_num = false;
                if k + 1 < len && bytes[k] == b'0' && (bytes[k + 1] == b'x' || bytes[k + 1] == b'X') {
                    k += 2;
                    let s = k;
                    while k < len && (bytes[k].is_ascii_hexdigit() || bytes[k] == b'_') { k += 1; }
                    is_num = k > s;
                } else if k + 1 < len && bytes[k] == b'0' && (bytes[k + 1] == b'b' || bytes[k + 1] == b'B') {
                    k += 2;
                    let s = k;
                    while k < len && (bytes[k] == b'0' || bytes[k] == b'1' || bytes[k] == b'_') { k += 1; }
                    is_num = k > s;
                } else {
                    let s = k;
                    let mut seen_digit = false;
                    while k < len && (bytes[k].is_ascii_digit() || bytes[k] == b'_' || bytes[k] == b'.') {
                        if bytes[k].is_ascii_digit() { seen_digit = true; }
                        k += 1;
                    }
                    is_num = seen_digit;
                    if is_num && k < len && (bytes[k] == b'e' || bytes[k] == b'E') {
                        let e = k + 1;
                        let mut m = e;
                        if m < len && (bytes[m] == b'+' || bytes[m] == b'-') { m += 1; }
                        let s2 = m;
                        while m < len && (bytes[m].is_ascii_digit() || bytes[m] == b'_') { m += 1; }
                        if m > s2 { k = m; }
                    }
                    let _ = s;
                }
                if is_num && k > body && k < len && bytes[k] == b']' {
                    if rng.gen_bool(0.7) {
                        flush(&mut out, code, last, i);
                        out.push('(');
                        out.push_str(&code[i..j]);
                        out.push(')');
                        i = j; last = j; continue;
                    }
                }
            }
            i = j;
            continue;
        }

        i += 1;
    }

    flush(&mut out, code, last, len);
    out
}


#[cfg(test)]
mod tests {
    use super::wrap_misc;

    fn code_hex_literals(src: &str) -> Vec<String> {
        // 粗略提取：跳过字符串与注释后的 0x.. 字面量
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0usize;
        let n = bytes.len();
        while i < n {
            if bytes[i] == b'"' || bytes[i] == b'\'' {
                let q = bytes[i];
                i += 1;
                while i < n {
                    if bytes[i] == b'\\' { i += 2; continue; }
                    if bytes[i] == q || bytes[i] == b'\n' { i += 1; break; }
                    i += 1;
                }
                continue;
            }
            if bytes[i] == b'0' && i + 1 < n && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                let mut end = i + 2;
                while end < n && (bytes[end].is_ascii_hexdigit() || bytes[end] == b'_') { end += 1; }
                if end > i + 2 { out.push(src[i..end].to_string()); }
                i = end; continue;
            }
            i += 1;
        }
        out
    }

    #[test]
    fn hex_literals_remain_valid() {
        let src = "local a = 0xDEADBEEF
local b = 0x1f + 0x1F
local c = 0xABCDE12 + 0x5 + 0x0e5
local d = 0XCAFE + 0x0Ab
local e = a + b + c + d";
        for _ in 0..200 {
            let out = wrap_misc(src);
            let lits = code_hex_literals(&out);
            assert!(lits.len() >= 7, "字面量太少: {out}");
            for lit in &lits {
                let us = lit.chars().filter(|&c| c == '_').count();
                assert!(us <= 2, "下划线超过 2 个: {lit}");
                let body: String = lit[2..].chars().filter(|&c| c != '_').collect();
                u64::from_str_radix(&body, 16).expect("去 _ 后必须是合法十六进制数");
            }
        }
    }

    #[test]
    fn hex_underscore_cap_distribution() {
        let src = "local a = 0xdeadbeef";
        let mut with_us = 0usize;
        let tries = 400;
        for _ in 0..tries {
            let out = wrap_misc(src);
            let lits = code_hex_literals(&out);
            if lits[0].contains('_') { with_us += 1; }
        }
        // 70% 目标概率：放宽到 40%~95% 区间（样本波动大）
        let ratio = with_us as f64 / tries as f64;
        assert!(ratio > 0.40 && ratio < 0.95, "带下划线比例异常: {ratio}");
    }

    #[test]
    fn hex_case_is_randomized() {
        let src = "local a = 0xabcdef + 0xABCDEF";
        let mut saw_upper = false;
        let mut saw_lower = false;
        for _ in 0..200 {
            let out = wrap_misc(src);
            let lits = code_hex_literals(&out);
            for lit in &lits {
                let letters: String = lit[2..].chars().filter(|c| c.is_ascii_alphabetic()).collect();
                if letters.chars().any(|c| c.is_ascii_uppercase()) { saw_upper = true; }
                if letters.chars().any(|c| c.is_ascii_lowercase()) { saw_lower = true; }
            }
        }
        assert!(saw_upper && saw_lower, "大小写没有同时出现");
    }

    #[test]
    fn payload_strings_untouched() {
        let src = r#"local s = "0xdeadbeef" local c = 0xdeadbeef"#;
        for _ in 0..50 {
            let out = wrap_misc(src);
            let lits = code_hex_literals(&out);
            assert_eq!(lits.len(), 1, "代码区应有且仅有 1 个字面量: {out}");
            let string_payload = "0xdeadbeef";
            assert!(out.contains(string_payload), "字符串内容被改写: {out}");
        }
    }
}

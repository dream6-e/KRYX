// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 数字字面量混淆：生成 Luau 可解析的二进制数字字面量。
//!
//! Luau 词法分析器把 `[0-9._]+[A-Za-z0-9_]*` 当作同一个 number token，
//! 且解析前会先剥离所有的 `_`（见 vendor/luau-0.735/Ast/src/Parser.cpp 的 parseNumber）。
//! 因此 `_` 可以合法出现在数字的任意位置（`0b_01`、`0b0_1`、`0b01_` 都可以），
//! `b`/`B` 大小写随机；每个字面量最多 2 个 `_`（0/1/2 随机），位置随机且不重复。
//! 注意：数字后紧跟 `[A-Za-z0-9_]` 会被并入同一个 token，调用方必须保证数字后有 `)`、`]`、
//! `,`、`;`、空白等分隔符（当前所有调用点均满足；见 VM 中 format_num 的使用位置）。

use rand::Rng;

/// 生成随机的二进制数字字面量：前缀 `0b`/`0B`（大小写随机），
/// 每个字面量最多 2 个 `_`（0/1/2 个随机），位置随机分布（前缀之后的任意间隙或末尾，不重复）。
/// 返回值不含符号，`val` 由调用方先取绝对值。
pub(crate) fn random_binary_literal(val: u64) -> String {
    let body = format!("{:b}", val);
    let mut rng = rand::rng();

    // s = "0" + ("b"|"B") + body
    let mut s = String::with_capacity(body.len() + 2);
    s.push('0');
    s.push(if rng.random::<bool>() { 'b' } else { 'B' });
    s.push_str(&body);

    // 候选插入位置：s 下标 2..=s.len()（插入到该字符之前；== s.len() 表示末尾）。
    // 注意不含 s 下标 1（b/B 前缀字符），即不允许在 '0' 与前缀之间插入 '_'
    //（"0_b1010" Lua 能解析，但 compressor 的极简 lexer 不认，且没有必要保留）。
    let s_len = s.len();
    let mut gaps: Vec<usize> = (2..=s_len).collect();

    // 每个字面量最多 2 个 '_'，个数 0/1/2 均匀随机
    let want = rng.random_range(0..=2usize).min(gaps.len());
    // 局部 Fisher-Yates，随机选出 want 个不重复位置
    for i in 0..want {
        let j = rng.random_range(i..gaps.len());
        gaps.swap(i, j);
    }
    let chosen = &gaps[..want];

    let mut out = String::with_capacity(s.len() + want);
    for (i, c) in s.chars().enumerate() {
        if chosen.contains(&i) {
            out.push('_');
        }
        out.push(c);
    }
    if chosen.contains(&s_len) {
        out.push('_');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::random_binary_literal;

    fn strip_underscores(s: &str) -> String {
        s.chars().filter(|&c| c != '_').collect()
    }

    #[test]
    fn binary_literal_roundtrip() {
        let values: [u64; 8] = [0, 1, 2, 5, 255, 4096, 4294967295, 0x7FFF_FFFF_FFFF];
        for &v in &values {
            for _ in 0..200 {
                let lit = random_binary_literal(v);
                let stripped = strip_underscores(&lit);
                assert!(stripped.starts_with("0b") || stripped.starts_with("0B"), "前缀非法: {lit}");
                let body = &stripped[2..];
                assert!(!body.is_empty(), "二进制体为空: {lit}");
                let parsed = u64::from_str_radix(body, 2).expect("去掉 _ 后必须是合法二进制数");
                assert_eq!(parsed, v, "去 _ 解析结果不一致: {lit}");
                assert!(lit.chars().all(|c| c == '0' || c == '1' || c == '_' || c == 'b' || c == 'B'),
                    "字面量含非法字符: {lit}");
                assert!(lit.chars().filter(|&c| c == '_').count() <= 2,
                    "字面量 _ 数量超过 2 个: {lit}");
            }
        }
    }

    #[test]
    fn case_and_underscore_vary() {
        let mut saw_lower = false;
        let mut saw_upper = false;
        let mut saw_underscore = false;
        let mut saw_plain = false;
        for _ in 0..500 {
            let lit = random_binary_literal(0b1010_1010);
            if lit.starts_with("0b") { saw_lower = true; } else { saw_upper = true; }
            if lit.contains('_') { saw_underscore = true; } else { saw_plain = true; }
        }
        assert!(saw_lower && saw_upper, "b/B 大小写没有同时出现");
        assert!(saw_underscore && saw_plain, "未同时出现带 _ 与不带 _ 的形式");
    }
}

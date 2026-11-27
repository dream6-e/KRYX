// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 入口收尾：执行器包裹（pcall + 错误重写）+ 无害三分支状态机。
//!
//! 对齐 sample2 的入口尾部两段形态：
//!
//! 1. `_P` 结尾那段 pcall + 错误重写：
//!    ```lua
//!    if K[24](P)~='string' then K[33](P,0X0)
//!    else
//!      if not(K[0xc](P,":数字[:行号]")) then K[33](P,0X0)
//!      else K[0X21]("Lua script:"..(H[F] or '(internal)')..": "..K[0b11101](P), 0X0)
//!    ```
//!    效果是把 VM 内部报错重写成「Kryx script: <位置>: <消息>」，掩盖真实出错点。
//!
//! 2. `J` 末尾那段 `while true do` 三分支状态机：
//!    两个分支 `continue`、一个 `break`，实际什么也不做，只留一个循环的假象。

/// 把一段纯字母文本渲染成「多转义混用」的 Lua 字符串字面量。
///
/// 对齐 sample2 的 `"\L\u{75}r\x61\z\x70h \83cr\z \105\zpt:"` —— 同一个词里
/// 十进制转义、十六进制转义、三位十进制补零转义、`\u{..}` 定点转义、`\z` 吞空白
/// 交替出现，读的人无法直接看出内容。
///
/// 逐个字符按 `variants()` 选一种写法：
///   0 十进制 `\76`
///   1 十六进制 `\x4C`
///   2 三位十进制 `\114`（Lua 的 `\ddd` 是十进制，不是 C 的八进制）
///   3 定点 `\u{4C}`
///   4 原样输出
/// 另外按 `z_at()` 随机插入 `\z `（`\z` 吞掉其后全部空白，不改变内容，
/// 只把字面量的字节形态打碎）。
pub fn escaped_literal(
    text: &str,
    variants: &mut impl FnMut() -> u8,
    z_at: &mut impl FnMut() -> bool,
) -> String {
    escaped_literal_q(text, variants, z_at, '"')
}

/// 同 `escaped_literal`，但可指定输出用的引号（`'` 或 `"`）。
///
/// sample2 的报错改写字面量单双引号是混用的（`'stri\x6E\103'` 用单引号、
/// `"\L\u{75}r\x61..."` 用双引号），所以引号也交给调用方随机。
///
/// ## 形态分布
///
/// 按 sample2 报错改写段四个字面量的实测统计来抽（合计 53 个 token）：
///
/// | 形态 | sample2 占比 |
/// |---|---|
/// | 原样输出 | 64.2% |
/// | `\xHH` | 15.1% |
/// | `\ddd`（十进制，最多 3 位） | 7.5% |
/// | `\u{..}` | 1.9% |
/// | `\z` | 11.3% |
///
/// 此前是五档等概率，实测原样只剩 ~20%，整段几乎全被转义，与 sample2
/// 的观感差很远。这里把 `variants()` 的返回值当 0..=99 的均匀源重新映射：
///
/// * `0..=63`   原样（64%）
/// * `64..=78`  `\xHH`（15%）
/// * `79..=86`  `\ddd`（8%）
/// * `87..=88`  `\u{..}`（2%）
/// * `89..=99`  原样（11%，留给 `\z` 的份额不占用形态档）
///
/// `\z` 由 `z_at()` 独立控制（调用方把概率调成 ~11%），它只是插在字符
/// 之间而不消耗形态档。
///
/// ## 正确性约束
///
/// 1. `\z` 会吞掉其后全部空白，所以 `\z` 之后紧跟的空白字符必须转义。
/// 2. 选中引号本身、反斜杠、控制字符（含换行）不能原样输出。
/// 3. 十进制转义后紧跟原样数字会粘连（`\040` + `4` → `\0404`），要强制转义。
pub fn escaped_literal_q(
    text: &str,
    variants: &mut impl FnMut() -> u8,
    z_at: &mut impl FnMut() -> bool,
    quote: char,
) -> String {
    let mut out = String::with_capacity(text.len() * 3 + 8);
    let mut prev_was_z = false;
    let mut prev_numeric = false;
    for (i, ch) in text.chars().enumerate() {
        let b = ch as u32;
        // 十进制/补零写法之后若跟原样数字会粘进同一个转义，必须避开。
        let sticky_digit = prev_numeric && ch.is_ascii_digit();
        // 不能原样输出的字符：引号本身、反斜杠、控制字符。
        let must_escape = ch == quote || ch == '\\' || (b < 0x20) || b == 0x7f;

        if i > 0 && z_at() {
            out.push('\\');
            out.push('z');
            out.push(' ');
            prev_was_z = true;
        } else {
            prev_was_z = false;
        }

        // 档位分配（合计 100）：原样 64 / \x 15 / \ddd 15 / \u{} 2 / 原样 4。
        // `\ddd` 给了 15 档而不是实测的 7.5%，因为 b > 99 的字符（标点、
        // 大写字母等）不能走 `\ddd`，会被降级成 `\xHH`；放大档位才能让
        // 最终产出里 `\ddd` 的实际占比落在 sample2 的水平。
        let roll = variants() % 100;
        let mut v: u8 = if roll < 64 {
            4
        } else if roll < 79 {
            1
        } else if roll < 94 {
            2
        } else if roll < 96 {
            3
        } else {
            4
        };
        // `\z` 后的空白会被吞掉，改走 `\xHH`。
        if v == 4 && prev_was_z && ch.is_whitespace() {
            v = 1;
        }
        // 不能原样输出的字符一律走 `\xHH`（定长两位，绝不会粘连）。
        if must_escape {
            v = 1;
        }
        if v == 4 && sticky_digit {
            v = 1;
        }
        // Lua 的 `\ddd` 最多三位、上限 255，所以任何 ASCII 字符都能用三位
        // 十进制写（统一补零成三位，后面必然是非数字或另一个转义的 `\`，
        // 不会粘连）。早前限制到 <= 99 是为了凑两位，但那样 `\ddd` 只能
        // 覆盖一半字符，实际占比远低于目标。
        if v == 2 && b > 255 {
            v = 1;
        }

        prev_numeric = false;
        match v {
            1 => {
                out.push_str(&format!("\\x{:02X}", b));
                prev_numeric = false;
            }
            2 => {
                out.push_str(&format!("\\{:03}", b));
                prev_numeric = true;
            }
            3 => {
                out.push_str(&format!("\\u{{{:X}}}", b));
                prev_numeric = false;
            }
            _ => {
                out.push(ch);
                prev_numeric = false;
            }
        }
    }
    out
}

/// 渲染报错改写用到的全部字面量，供 `wrap_entry` 嵌进生成的 Lua。
///
/// 返回 `(品牌前缀, internal 兜底, "string", ":", 位置匹配模式)`。
/// 连 `"string"`、`":"` 和 `":([0-9]+)[^0-9]*$"` 这种「结构性」字面量也一并
/// 走多转义渲染 —— sample2 里连分隔符都是转义形态的。
pub fn escaped_parts(
    variants: &mut impl FnMut() -> u8,
    z_at: &mut impl FnMut() -> bool,
) -> (String, String, String, String, String) {
    // 引号在单/双之间随机 —— sample2 里两种并存
    // （`'stri\x6E\103'` 用单引号，`"\L\u{75}r\x61..."` 用双引号）。
    //
    // 注意：字面量内容里可能含引号（模式串 `[^0-9]*$` 不含，但为了稳妥
    // 仍做转义处理）—— 选中的引号本身若出现在内容里，改用另一种引号。
    // 引号用 variants() 的低位单独决定，不走 z_at() —— 否则每取一次引号
    // 都会额外消耗一个 `\z` 的熵，把实际插入密度压低到目标值以下。
    let mut q = |t: &str| {
        let quote = if variants() % 2 == 0 { '\'' } else { '"' };
        let inner = escaped_literal_q(t, variants, z_at, quote);
        format!("{}{}{}", quote, inner, quote)
    };
    let tag = q("Kryx script");
    let inner = q("internal");
    let ty = q("string");
    let colon = q(":");
    let pat = q(":([0-9]+)[^0-9]*$");
    (tag, inner, ty, colon, pat)
}

/// 第 7 项：执行器包裹。
///
/// 先生成「偏应用」（第 5 项）：`(function(f,h) return function(...) return f(h,...) end end)(exec, chunk)`
/// 再 pcall 它；出错时尝试从错误串里取出 `:数字` 形式的位置，重抛成
/// `Kryx script:<位置>: <消息>`，取不到位置就原样重抛。
#[allow(clippy::too_many_arguments)]
pub fn wrap_entry(
    wr: &str,
    ok: &str,
    msg: &str,
    pos: &str,
    hold: &str,
    shift: &str,
    pcall_expr: &str,
    exec: &str,
    benv: &str,
    l: &str,
    type_expr: &str,
    match_expr: &str,
    tostring_expr: &str,
    error_expr: &str,
    lit_tag: &str,
    lit_internal: &str,
    lit_string_ty: &str,
    lit_colon: &str,
    lit_pattern: &str,
) -> String {
    format!(
        "local function {wr}(...) \
            local {hold} = (function(f, h) return function({shift}, ...) return f(h, ...) end end)({exec}, main_chunk); \
            local {ok},{msg} = {pcall_expr}({hold}, {benv}, {{}}, {l}, ...); \
            if {ok} then return {msg} end; \
            local {pos} = ({type_expr}({msg})=={lit_string_ty}) and {match_expr}({msg}, {lit_pattern}) or nil; \
            if {pos} then \
                {error_expr}({lit_tag}..{lit_colon}..{pos}..{lit_colon}..' '..{tostring_expr}({msg})); \
            end; \
            if {pos}==nil then \
                {error_expr}({lit_tag}..{lit_colon}..' ('..{lit_internal}..')'..{lit_colon}..' '..{tostring_expr}({msg})); \
            end; \
            {error_expr}({msg}); \
        end; "
    )
}

/// 第 4 项：无害三分支状态机。
///
/// 三个分支分别是「写槽位 + break」「写槽位 + 改状态 + continue」
/// 「恒真判断里写槽位 + 改状态 + continue」，都能在有限步内退出，
/// 保证不会死循环（这一点在早期实现里踩过坑）。
pub struct StateMachine {
    pub st: String,
    pub mid: usize,
    pub lo: usize,
    pub hi: usize,
    pub reg: String,
    pub key: usize,
    pub rrot: String,
    pub cntrz: String,
    pub band: String,
}

impl StateMachine {
    pub fn render(&self) -> String {
        format!(
            "local {st}={mid}; while true do \
                if {st}>{mid} then ({reg})[{k}]=({rrot}); break; \
                elseif {st}<{mid} then ({reg})[{k2}]=({cntrz}); {st}={hi}; continue; \
                else if not({st}>{lo} and {st}<{hii}) then {st}={hi}; \
                else ({reg})[{k3}]=({band}); {st}={hi}; continue; end; end; end; ",
            st = self.st,
            mid = self.mid,
            lo = self.lo,
            hi = self.hi,
            hii = self.hi + 9,
            reg = self.reg,
            k = self.key,
            k2 = self.key + 1,
            k3 = self.key + 2,
            rrot = self.rrot,
            cntrz = self.cntrz,
            band = self.band,
        )
    }
}

/// 一次性渲染整段入口包裹（含转义字面量与种子）。
///
/// `shell_keys` = `[pcall, type, match, tostring, error]`
/// `names`      = `[wrap_fn, exec, benv, l, ok, msg, pos, hold]`
///
/// 抽到本模块是为了让 `impl_generator.rs` 保持在 45 KB 以内。
pub fn render_entry(
    rng: &mut super::GenRng,
    var_shell: &str,
    shell_keys: [&str; 5],
    names: [&str; 8],
) -> String {
    // 形态档：0..=99 的均匀源，由 escaped_literal_q 按 sample2 的实测分布
    // 重新映射（原样 64% / \x 15% / \ddd 15% / \u{} 2%）。
    //
    // 池子取 300 个（100 的整数倍）而不是 128：128 不是 100 的倍数，
    // `% 100` 会让某些档位系统性偏多。五个字面量一共只用掉 ~45 次抽取，
    // 300 足够避免「循环复用同一段模式」导致的整段分布被绑定。
    let mut esc_variants: Vec<u8> = (0..300).map(|_| rng.range(0, 100) as u8).collect();
    // `\z` 按 sample2 实测的 11.3% 插入（原先 25%，明显偏密）。
    //
    // 这里**不用预采样表**：五个字面量一共只有 ~48 次判定，从固定序列里
    // 取前 48 个，实测命中率在 0%~4% 与 14% 之间大幅抖动（20 次生成汇总
    // 只有 7.1%，低于目标 11.3%）。改成每次判定独立取一个随机数，
    // 期望值就是 11%，不再依赖序列前段的偶然分布。
    let mut vi = 0usize;
    let (lit_tag, lit_inner, lit_ty, lit_colon, lit_pat) = escaped_parts(
        &mut || { let v = esc_variants[vi % esc_variants.len()]; vi += 1; v },
        &mut || rng.range(0, 100) < 11,
    );
    let k = |i: usize| format!("{}.{}", var_shell, shell_keys[i]);
    wrap_entry(
        names[0], names[4], names[5], names[6], names[7], "_",
        &k(0), names[1], names[2], names[3],
        &k(1), &k(2), &k(3), &k(4),
        &lit_tag, &lit_inner, &lit_ty, &lit_colon, &lit_pat,
    )
}

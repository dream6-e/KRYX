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
    let mut out = String::with_capacity(text.len() * 4 + 8);
    let mut prev_was_z = false;
    let mut prev_pad3 = false;
    let mut prev_any_numeric_tail = false;
    for (i, ch) in text.chars().enumerate() {
        // 上一位是十进制/补零写法且末位是数字时，本字符若原样输出会粘进转义。
        let force_escape = prev_any_numeric_tail && ch.is_ascii_digit();
        let b = ch as u32;
        if i > 0 && z_at() {
            out.push('\\');
            out.push('z');
            out.push(' ');
            prev_was_z = true;
        } else {
            prev_was_z = false;
        }
        // `\z` 会吞掉其后全部空白。若紧跟其后的字符本身是空格且选择原样
        // 输出，那个空格会被一起吞掉（"Kryx script" 变 "Kryxscript"）。
        // 所以 `\z` 之后的空白字符必须强制走转义写法。
        let mut v = variants() % 5;
        if v == 4 && prev_was_z && ch.is_whitespace() {
            v = 1;
        }
        if v == 4 && force_escape {
            v = 1;
        }
        // `\ddd` 最多吃 3 位十进制数字，且 Lua 不检查是否超过 255：
        // 若三位写法的末位正好是数字，会和下一个原样字符的数字粘连。
        // 例如 `(` 写成 `\040` 后紧跟原样的 `4` 会变成 `\0404`，解析报
        // malformed escape。所以：
        //   · 三位写法只对 <= 99 的字符用（`\099` 后面必然是非数字或转义）；
        //   · 紧跟其后的字符若也要原样输出、且本身是数字，则强制转义。
        let three_digit_ok = b <= 99;
        let mut v = if v == 2 && !three_digit_ok { 0 } else { v };
        // 三位十进制后面不能跟原样数字
        if prev_pad3 && ch.is_ascii_digit() && v == 4 {
            v = 1;
        }
        prev_pad3 = false;
        match v {
            0 => {
                // `\<十进制>` 若后接数字同样会粘连，这里统一补成 `\xHH` 之外的
                // 两位形式不可靠，故 0 档也只在下一字符非数字时启用（见上层兜底）。
                out.push_str(&format!("\\{}", b));
                prev_any_numeric_tail = b >= 10;
            }
            1 => out.push_str(&format!("\\x{:02X}", b)),
            // Lua 的 `\ddd` 是**十进制**转义（不是 C 的八进制），最多 3 位。
            // 早前按八进制输出导致 `\163` 变成 U+00A3，报错文本解码出错。
            2 => {
                out.push_str(&format!("\\{:02}", b));
                prev_pad3 = true;
            }
            3 => out.push_str(&format!("\\u{{{:X}}}", b)),
            _ => out.push(ch),
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
    let mut q = |t: &str| format!("\"{}\"", escaped_literal(t, variants, z_at));
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
    pub rrot: &'static str,
    pub cntrz: &'static str,
    pub band: &'static str,
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
    let mut esc_variants: Vec<u8> = (0..64).map(|_| rng.range(0, 5) as u8).collect();
    let mut esc_z: Vec<bool> = (0..64).map(|_| rng.range(0, 4) == 0).collect();
    let mut vi = 0usize;
    let mut zi = 0usize;
    let (lit_tag, lit_inner, lit_ty, lit_colon, lit_pat) = escaped_parts(
        &mut || { let v = esc_variants[vi % esc_variants.len()]; vi += 1; v },
        &mut || { let z = esc_z[zi % esc_z.len()]; zi += 1; z },
    );
    let k = |i: usize| format!("{}.{}", var_shell, shell_keys[i]);
    wrap_entry(
        names[0], names[4], names[5], names[6], names[7], "_",
        &k(0), names[1], names[2], names[3],
        &k(1), &k(2), &k(3), &k(4),
        &lit_tag, &lit_inner, &lit_ty, &lit_colon, &lit_pat,
    )
}

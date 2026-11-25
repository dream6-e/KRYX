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
//!    效果是把 VM 内部报错重写成「Lua script: <位置>: <消息>」，掩盖真实出错点。
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
    for (i, ch) in text.chars().enumerate() {
        let b = ch as u32;
        if i > 0 && z_at() {
            out.push('\\');
            out.push('z');
            out.push(' ');
        }
        match variants() % 5 {
            0 => out.push_str(&format!("\\{}", b)),
            1 => out.push_str(&format!("\\x{:02X}", b)),
            // Lua 的 `\ddd` 是**十进制**转义（不是 C 的八进制），最多 3 位。
            // 早前按八进制输出导致 `\163` 变成 U+00A3，报错文本解码出错。
            2 => out.push_str(&format!("\\{:03}", b)),
            3 => out.push_str(&format!("\\u{{{:X}}}", b)),
            _ => out.push(ch),
        }
    }
    out
}

/// 渲染 `Lua script` / `internal` 两段，供 `wrap_entry` 嵌进生成的 Lua。
pub fn escaped_parts(
    variants: &mut impl FnMut() -> u8,
    z_at: &mut impl FnMut() -> bool,
) -> (String, String) {
    let q = |t: String| format!("\"{}\"", t.replace('"', "\\\""));
    (
        q(escaped_literal("Lua script", variants, z_at)),
        q(escaped_literal("internal", variants, z_at)),
    )
}

/// 第 7 项：执行器包裹。
///
/// 先生成「偏应用」（第 5 项）：`(function(f,h) return function(...) return f(h,...) end end)(exec, chunk)`
/// 再 pcall 它；出错时尝试从错误串里取出 `:数字` 形式的位置，重抛成
/// `Lua script:<位置>: <消息>`，取不到位置就原样重抛。
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
) -> String {
    format!(
        "local function {wr}(...) \
            local {hold} = (function(f, h) return function({shift}, ...) return f(h, ...) end end)({exec}, main_chunk); \
            local {ok},{msg} = {pcall_expr}({hold}, {benv}, {{}}, {l}, ...); \
            if {ok} then return {msg} end; \
            local {pos} = ({type_expr}({msg})=='string') and {match_expr}({msg}, ':([0-9]+)[^0-9]*$') or nil; \
            if {pos} then \
                {error_expr}({lit_tag}..':'..{pos}..': '..{tostring_expr}({msg})); \
            end; \
            if {pos}==nil then \
                {error_expr}({lit_tag}..': ('..{lit_internal}..'): '..{tostring_expr}({msg})); \
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

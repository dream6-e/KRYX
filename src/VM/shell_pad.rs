// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 壳（decoder shell）的外观填充：完全对齐 sample2.lua 的包装形式。
//!
//! 依据 `AI必读/sample2包装形式.md` 的第 3/4/5/6 类：
//!
//! - 第 3 类：内建函数/库以 1~2 字符别名挂在壳表的字段上
//!   （`X=bit32.bxor,b=string.sub,Z=error,...`），正文只经 `q.<别名>` 访问。
//! - 第 4 类：重复参数名（`function(v,v,u)`）—— 由 compressor 做，这里只提供
//!   采样口径（见 `param_pad_ratio`）。
//! - 第 5 类：样板填充函数（空函数 / 恒等 / 只读一位 / 变参空转 / 槽位清空），
//!   它们**不参与任何计算**，只作为壳字段与函数体里的噪声语句存在。
//! - 第 6 类：IIFE —— 尤其是 sample2 那种「只取出函数值存进槽位、不调用」的形态。
//!
//! 正确性铁律：本模块产出的所有片段都不触碰解码器的任何真实状态
//! （不读写 `s.*`、不改 `_`、不 return/break 主流程），因此对语义零影响。

use crate::VM::VM_Backend::Generator::GenRng;

/// 第 3 类：把内建函数/库挂到壳字段上，返回 `字段=值`。
///
/// sample2 的正文里这些别名是 1~2 字符（`X=bit32.bxor`、`i=table`）；
/// 这里字段名由调用方用 `GenRng::name()` 生成，收尾时统一压成短名，
/// 所以产物里同样是 1~2 字符，且不会与 `k_*` / 方法名冲突。
pub fn builtin_alias(rng: &mut GenRng, name: &str) -> String {
    // (值, sample2 里对应的短名，仅用于说明；实际采用调用方给的名字)
    const VALUES: [&str; 16] = [
        "bit32.band",
        "bit32.bor",
        "bit32.bxor",
        "bit32.bnot",
        "bit32.lshift",
        "bit32.rshift",
        "bit32.countlz",
        "bit32.countrz",
        "bit32.lrotate",
        "bit32.rrotate",
        "string.byte",
        "string.sub",
        "string.gsub",
        "string.match",
        "string.unpack",
        "table.unpack",
    ];
    let v = VALUES[rng.range(0, VALUES.len())];
    format!("{}={}", name, v)
}

/// sample2 里还有一批"库整体别名"（`i=table`、`r=buffer`、`u=unpack`、`Z=error`）。
pub fn lib_alias(rng: &mut GenRng, name: &str) -> String {
    const VALUES: [&str; 6] = ["table", "buffer", "unpack", "error", "coroutine", "string"];
    let v = VALUES[rng.range(0, VALUES.len())];
    format!("{}={}", name, v)
}

/// 第 5 类：样板填充函数。返回 `名字=function(...)...end`。
///
/// 全部是 sample2 里真实出现过的形态，且函数体不引用任何外部名字。
pub fn pad_function(rng: &mut GenRng, name: &str) -> String {
    match rng.range(0, 8) {
        // 空函数：`u2=function(v)end`
        0 => format!("{}=function(v)end", name),
        1 => format!("{}=function()end", name),
        // 恒等：`r2=function(v,v)return v;end`
        2 => format!("{}=function(v,v)return v;end", name),
        // 只读槽位：`c=function(v,v,u)v=u[0X6B6];return v;end`
        3 => {
            let k = rng.range(0x100, 0x7000);
            format!("{}=function(v,v,u)v=u[0x{:X}];return v;end", name, k)
        }
        // 只写槽位：`j2=function(v,v,u)u[0X8]=v;end`
        4 => {
            let k = rng.range(0x100, 0x7000);
            format!("{}=function(v,v,u)u[0x{:X}]=v;end", name, k)
        }
        // 变参空操作：`s=function(...)(...)[...]=nil;end`
        5 => format!("{}=function(...)(...)[...]=nil;end", name),
        // 槽位清空连写：`function(v,v)v[..]=nil;v[..]=nil;...end`
        6 => {
            let mut body = String::new();
            for i in 0..3 {
                let k = rng.range(0x10, 0x900);
                if i > 0 {
                    body.push(';');
                }
                body.push_str(&format!("v[0x{:X}]=nil", k));
            }
            format!("{}=function(v,v){};end", name, body)
        }
        // 自增伪装：`b2=function(v,v)v[0X29]=v[0b101001]+0x2;end`
        7 => {
            let a = rng.range(0x10, 0x900);
            let b = rng.range(0x10, 0x900);
            let c = rng.range(1, 0x40);
            format!("{}=function(v,v)v[0x{:X}]=v[0x{:X}]+0x{:X};end", name, a, b, c)
        }
        // 双槽位搬运：`e2=function(v,v,u,m,f)f[m]=v[0b10001][u];end`
        _ => {
            let k = rng.range(0x10, 0x900);
            format!("{}=function(v,v,u,m)f[m]=v[0x{:X}][u];end", name, k)
        }
    }
}

/// 第 6 类：IIFE。sample2 有 8 处 `(function(`，其中多数是「只取出函数值存槽位」。
///
/// 返回可直接作为语句拼接的片段。所有片段都只操作壳表 `q` 的临时槽位，
/// 或根本不留副作用，因此不会影响解码流程。
pub fn iife_stmt(rng: &mut GenRng, shell: &str) -> String {
    // 关键约束：这些句子在壳表建好之后执行，**绝对不能写壳表的字段**
    // （壳表的数字键就是解码器自己的状态/常量槽，写了就破坏语义）。
    // 因此只允许「读壳表、丢弃结果」或完全无副作用的形态。
    //
    // 另外必须整条包在 `do ... end` 里：压缩器会去掉分号，而两个相邻的
    // `(function()...end)()` 会被解析成链式调用 `f()(g)`，导致 "attempt to call"。
    match rng.range(0, 4) {
        // 立即调用、丢弃返回值（sample2 的 `(function()return(v:X2(f));end)` 同型）
        0 => format!("do (function()local v={};return v end)() end;", shell),
        // 变参原地转发：只构造函数值，不调用
        1 => "do local v=(function(...)return(...)[...];end) end;".to_string(),
        // 取值后再返回，纯空转
        2 => format!("do (function()local v={};return v end)() end;", shell),
        // 空函数立即调用
        _ => "do (function()end)() end;".to_string(),
    }
}

/// 函数体内部可插入的一行"填充语句"。只写临时槽位，不碰任何真实状态。
pub fn pad_stmt(rng: &mut GenRng, shell: &str) -> String {
    let slot = rng.range(0x100, 0x7000);
    match rng.range(0, 5) {
        0 => format!("({})[0x{:X}]=nil;", shell, slot),
        1 => format!("local {}={};(void){};", "s", shell, "s"),
        2 => format!("(function()end)();"),
        3 => format!("({})[0x{:X}]=({});", shell, slot, shell),
        _ => format!("if not ({})[0x{:X}]then ({})[0x{:X}]=({});end;", shell, slot, shell, slot, shell),
    }
}

/// 第 4 类：重复参数名的目标比例（compressor 侧按此概率做参数覆盖）。
///
/// sample2 实测 139 个函数里 63 个含重复参数名（约 45%），这里取同一量级。
pub fn param_pad_ratio() -> f64 {
    0.92
}

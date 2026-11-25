// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 入口表的数据字段池 + 随机穿插。
//!
//! sample2 的顶层表 `{RP=bit32.band, p2=function... , S2=function..., ...}` 里，
//! 「库别名」和「方法」是**随机穿插**的，没有明显的「方法区 / 数据区」分界。
//! 项目原来的收尾是把 `select` / `math.floor` / `pcall` / `bit32.*` 等数据字段
//! 整齐地排在所有方法后面，一眼就能看出边界。
//!
//! 这里把这份字段表外置，并提供 `interleave`：按随机 1~2 条一组切开，
//! 组间插入随机数量的空方法槽，使数据字段在方法区里均匀散开。

/// 一份数据字段：(字段名, 值表达式)。字段名由调用方传入（已随机化）。
pub struct DataField {
    pub name: String,
    pub value: &'static str,
}

/// 把数据字段随机穿插成表字面量的一段（每项自带前置 `,`）。
///
/// 不直接依赖 `rand::Rng`：调用方的 `GenRng` 不是 `Rng` 实现，
/// 所以这里只收两个闭包（`range(lo, hi)` 与 `fresh_name()`），
/// 随机源仍由调用方统一掌控。
pub fn interleave(
    fields: &mut [DataField],
    pad_names: &[String],
    mut range: impl FnMut(usize, usize) -> usize,
) -> String {
    // 先打散顺序：否则插入的间隔再随机，字段间的相对次序仍是固定的
    for i in (1..fields.len()).rev() {
        let j = range(0, i + 1);
        fields.swap(i, j);
    }
    let mut buf = String::new();
    let mut i = 0usize;
    while i < fields.len() {
        let take = range(1, 2.min(fields.len() - i) + 1);
        for _ in 0..take {
            let f = &fields[i];
            buf.push_str(&format!(",{}={}", f.name, f.value));
            i += 1;
        }
        // 随机数量的空方法槽：切断数据字段的连续性
        let pads = range(0, 3usize);
        for j in 0..pads {
            if let Some(nm) = pad_names.get(j) {
                buf.push_str(&format!(",{}=function(...)end", nm));
            }
        }
    }
    buf
}

/// 项目的全部数据字段（值表达式沿用原样，保证环境兼容语义不变）。
/// 传入 15 个已随机化的字段名，顺序与下方的值一一对应。
pub fn all_fields(k: [&String; 20]) -> Vec<DataField> {
    const VALUES: [&str; 20] = [
        "select",
        "math.floor",
        "math.random",
        "string.char",
        "string.byte",
        "string.sub",
        "table.concat",
        "unpack or table and table.unpack or function() end",
        "pcall",
        "setmetatable",
        "type",
        "pairs",
        "string.match",
        "tostring",
        "error",
        // KX1 反调试池解密所需（bit32 缺失时回退等价实现）
        "bit32 and bit32.countlz or function(a_) a_=a_%4294967296;local n=0;while a_>0 and a_<2147483648 do a_=a_*2;n=n+1 end;return n end",
        "bit32 and bit32.countrz or function(a_) a_=a_%4294967296;local n=0;while n<32 and a_%2==0 do a_=a_/2;n=n+1 end;return n end",
        "bit32 and bit32.byteswap or function(a_) a_=a_%4294967296;local b1=a_%256;local b2=(a_%65536-b1)/256;local b3=(a_%16777216-a_%65536)/65536;local b4=(a_-a_%16777216)/16777216;return b1*16777216+b2*65536+b3*256+b4 end",
        "bit32 and bit32.lrotate or function(a_,n) a_=a_%4294967296;n=n%32;return (a_*(2^n))%4294967296+ (a_-a_%1)/(2^(32-n)) - (a_-a_%1)/(2^(32-n))%1 end",
        "bit32 and bit32.rrotate or function(a_,n) a_=a_%4294967296;n=n%32;return (a_-a_%1)/(2^n) + (a_%1) end",
    ];
    k.iter()
        .zip(VALUES.iter())
        .map(|(name, value)| DataField { name: name.to_string(), value })
        .collect()
}

/// bit32 系列兼容垫片（bit32 / bit 库都不存在时退回纯算术实现）。
/// 项目原本把这段内联在收尾处，体积占 ~2 KB，外置后主文件能回到 45 KB 以内。
pub fn bit32_shims(bx: &str, band: &str, bor: &str, lshift: &str, rshift: &str, bnot: &str) -> String {
    format!(
        ",{bx}=bit32 and bit32.bxor or function(a_,b_)a_,b_=a_%4294967296,b_%4294967296;local r,p=0,1;while a_>0 or b_>0 do local ra,rb=a_%2,b_%2;if ra~=rb then r=r+p end;a_,b_,p=(a_-a_%1)/2,(b_-b_%1)/2,p*2 end;return r end\
         ,{band}=bit32 and bit32.band or function(a_,b_)a_,b_=a_%4294967296,b_%4294967296;local r,p=0,1;while a_>0 and b_>0 do local ra,rb=a_%2,b_%2;if ra==1 and rb==1 then r=r+p end;a_,b_,p=(a_-a_%1)/2,(b_-b_%1)/2,p*2 end;return r end\
         ,{bor}=bit32 and bit32.bor or function(a_,b_)a_,b_=a_%4294967296,b_%4294967296;local r,p=0,1;while a_>0 or b_>0 do local ra,rb=a_%2,b_%2;if ra==1 or rb==1 then r=r+p end;a_,b_,p=(a_-a_%1)/2,(b_-b_%1)/2,p*2 end;return r end\
         ,{lshift}=bit32 and bit32.lshift or function(a_,n)a_=a_%4294967296;return (a_*(2^n))%4294967296 end\
         ,{rshift}=bit32 and bit32.rshift or function(a_,n)a_=a_%4294967296;return (a_ - a_ % (2^n)) / (2^n) end\
         ,{bnot}=bit32 and bit32.bnot or function(a_)a_=a_%4294967296;return 4294967295 - a_ end",
    )
}

/// 一步到位：构造字段表 → 打散 → 按随机间隔穿插出表字面量片段。
pub fn interleaved_fields(
    names: &[&String; 20],
    pad_names: &[String],
    range: impl FnMut(usize, usize) -> usize,
) -> String {
    let mut fields = all_fields(*names);
    interleave(&mut fields, pad_names, range)
}

/// KX1 反调试池解密额外需要的 5 个 bit32 字段名。
/// 放在本模块是为了让 `impl_generator.rs` 保持在 45 KB 以内。
pub struct Kx1Fields {
    pub cntlz: String,
    pub cntrz: String,
    pub swap: String,
    pub lrot: String,
    pub rrot: String,
}

impl Kx1Fields {
    pub fn new(rng: &mut super::GenRng) -> Self {
        Self {
            cntlz: rng.name(),
            cntrz: rng.name(),
            swap: rng.name(),
            lrot: rng.name(),
            rrot: rng.name(),
        }
    }
    pub fn names(&self) -> [&str; 5] {
        [&self.cntlz, &self.cntrz, &self.swap, &self.lrot, &self.rrot]
    }
}

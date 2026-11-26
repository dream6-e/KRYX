// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! KX1 的 Rust 侧实现，用于加密反调试池。
//!
//! 算法见 `cipher/kx1.lua`。Lua 侧解密函数由本模块的 `lua_decrypt_body`
//! 生成 —— **两边必须逐位一致**，否则池解不开、guard 全部走 bad 分支。
//!
//! 实现时踩过的坑（都已实测确认）：
//!   * Lua 的 `bit32.lshift(x, n)` 对 n>=32 返回 0（不掩码），Rust 的
//!     `wrapping_shl` 会掩码成 n%32 —— 必须显式判 n>=32。
//!   * Lua 的 `bit32.rrotate(x, n)` 掩码 n%32，与上面不同。
//!   * Lua 的 `%` 对负数是 floor 语义，Rust 的 `%` 是 trunc —— 负数索引用
//!     `rem_euclid`。
//!   * Lua 数字是 IEEE double，但本模块全部用 `u32` 整数运算并显式
//!     `wrapping_mul`，等价于 Lua 侧 `mul32` 的分肢实现（<=2^32 精确）。

const U32_MASK: u64 = 0xFFFF_FFFF;

const E: [u32; 8] = [
    0x6B72_797A, 0xC1F0_0000, 0x9E37_79B9, 0xC0FF_EE00,
    0xDEAD_BEEF, 0xA5A5_A5A5, 0x0123_4567, 0xCAFE_BABE,
];

const R: [u32; 16] = [5, 11, 17, 23, 29, 3, 13, 27, 7, 19, 31, 1, 9, 21, 15, 25];

const MA: u32 = 0x9E37_79B1;
const MB: u32 = 0x85EB_CA77;

/// Lua 语义的 `lshift`：n >= 32 时返回 0，而不是掩码。
#[inline]
fn lsh(x: u32, n: u32) -> u32 {
    if n >= 32 { 0 } else { x << n }
}

/// Lua 语义的 `rshift`：n >= 32 时返回 0。
#[inline]
fn rsh(x: u32, n: u32) -> u32 {
    if n >= 32 { 0 } else { x >> n }
}

/// Lua 语义的 `rrotate`：掩码 n%32。
#[inline]
fn rrot(x: u32, n: u32) -> u32 {
    x.rotate_right(n % 32)
}

/// Lua 语义的 `lrotate`：掩码 n%32。
#[inline]
fn lrot(x: u32, n: u32) -> u32 {
    x.rotate_left(n % 32)
}

#[inline]
fn cntlz(x: u32) -> u32 { x.leading_zeros() }

#[inline]
fn cntrz(x: u32) -> u32 { x.trailing_zeros() }

/// 与 Lua 侧 `mul32` 等价的精确 32 位乘法。
/// Lua 那边拆 16 位分肢；Rust 这边 `wrapping_mul` 天然精确，结果一致。
#[inline]
fn mul32(a: u32, b: u32) -> u32 { a.wrapping_mul(b) }

fn quarter(s: &mut [u32; 8], o: usize, k: u32, r1: u32, r2: u32, round: u32) {
    let (a, b, c, d) = (o, o + 1, o + 2, o + 3);
    s[a] = s[a].wrapping_add(s[b]);
    s[c] ^= lrot(s[a] ^ k, r1);
    s[b] = mul32(s[b], MA);
    s[d] = s[d].wrapping_add(s[c]);
    s[a] ^= rrot(s[d] ^ k, r2);
    s[c] = mul32(s[c], MB);
    // 关键：round*8 在第 5 轮起 >= 40，整项塌成 0。Rust 若用普通 << 会掩码。
    s[c] ^= lsh(r1.wrapping_add(r2), round * 8 + r1);
    s[c] ^= cntrz(s[a] | 1);
    s[a] ^= cntlz(s[c] | 1);
    s[d] = (s[d] & !s[a]).swap_bytes();
    s[b] = s[b].wrapping_add((s[d] % 65536).wrapping_mul(65537));
}

fn block_enc(kw: &[u32; 16], x: [u32; 8]) -> [u32; 8] {
    let mut s = x;
    for round in 1..=8u32 {
        let k = kw[((round * 3) % 16) as usize] ^ E[(round as usize) - 1]
            ^ mul32(round.wrapping_mul(0x0101_0101), E[(round % 8) as usize]);
        let r1 = R[((round * 2 - 1) % 16) as usize];
        let r2 = R[((round * 2) % 16) as usize];
        quarter(&mut s, 0, k, r1, r2, round);
        quarter(&mut s, 4, k, r2, r1, round);
        if round < 8 {
            s.swap(0, 4);
            s.swap(1, 5);
            s.swap(2, 6);
            s.swap(3, 7);
        }
    }
    s
}


/// 密钥调度，与 Lua 侧 `M.keywords` 逐位一致。
pub fn keywords(key: &[u8]) -> [u32; 16] {
    let n = if key.is_empty() { 1 } else { key.len() };
    let mut kw = [0u32; 16];
    for i in 1..=16usize {
        let mut w = (i as u32).wrapping_mul(0x0101_0101);
        for j in 0..4usize {
            let idx = ((i - 1) * 4 + j) % n + 1;
            let byte = if idx <= key.len() { key[idx - 1] as u32 } else { 0 };
            w ^= byte.wrapping_mul((j * 8 + 1) as u32);
        }
        kw[i - 1] = w;
    }
    for pass in 1..=3u32 {
        let mut lo = [0u32; 8];
        lo.copy_from_slice(&kw[0..8]);
        let r = block_enc(&kw, lo);
        kw[0..8].copy_from_slice(&r);
        let mut hi = [0u32; 8];
        hi.copy_from_slice(&kw[8..16]);
        let r = block_enc(&kw, hi);
        kw[8..16].copy_from_slice(&r);
        // 注意：Lua 侧写的是 `kw[i] = BXOR(kw[i], mul32(kw[i%16+1] + ...))`，
        // 其中 `kw[i%16+1]` 读的是**正在被改写的表**（i=0 时读 kw[1]，
        // 此时 kw[1] 还是旧值；i=1 时读 kw[2]，旧值……直到 i=15 读 kw[0]，
        // 而 kw[0] 已在 i=0 时被更新）。必须逐元素原地更新，不能用快照。
        for i in 0..16usize {
            // Lua: kw[i] ^= mul32(kw[i%16+1] + ..., E[i%8+1])
            // i 是 1 基，换到 0 基后 kw 下标是 (i+1)%16、E 下标是 (i+1)%8。
            kw[i] ^= mul32(kw[(i + 1) % 16].wrapping_add(pass.wrapping_mul(0x0101_0101)),
                           E[(i + 1) % 8]);
        }
    }
    kw
}

/// 生成 `len` 字节密钥流，与 Lua 侧 `M.stream` 逐位一致。
pub fn stream(kw: &[u32; 16], nonce: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut c0 = nonce;
    let mut c1 = nonce.swap_bytes();
    let mut blk: u32 = 0;
    while out.len() < len {
        c1 = c1.wrapping_add(1);
        if c1 == 0 { c0 = c0.wrapping_add(1); }
        let mix = (blk as i64 - 1).rem_euclid(8) as usize;
        let w = block_enc(kw, [
            c0 ^ mul32(blk.wrapping_add(1), E[mix]),
            c1 ^ mul32(blk.wrapping_add(1), E[(mix + 3) % 8]),
            c0 ^ c1,
            c0 & !c1,
            (c0.wrapping_add(blk)).swap_bytes(),
            mul32(c0, MA),
            mul32(c1, MB) ^ blk,
            (c0 | 1) ^ cntlz(c1 | 1),
        ]);
        for wi in w.iter() {
            for j in 0..4 {
                if out.len() >= len { return out; }
                out.push((rsh(*wi, j * 8) & 0xFF) as u8);
            }
        }
        blk = blk.wrapping_add(1);
    }
    out
}

/// 加密一段明文：`cipher = plain XOR keystream`。
pub fn encrypt(plain: &[u8], key: &[u8], nonce: u32) -> Vec<u8> {
    let kw = keywords(key);
    let ks = stream(&kw, nonce, plain.len());
    plain.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect()
}

/// 生成与 `cipher/kx1.lua` 等价的 Lua 解密函数体（不含 `function` 头）。
///
/// 参数：
///   `pool` —— 池表变量名
///   `key`  —— 16 个 32 位密钥字的字面量表（由调用方渲染成 Lua）
///   `nonce` —— 计数器初值
/// 把 8 个字节打包成一个可安全写进 Lua 源码的 double 字面量。
///
/// `bits` 是这 8 字节按小端拼出的 u64。IEEE-754 允许的位模式里有一小部分
/// 对应 NaN/Inf —— 它们 `tostring` 出来是 `nan`/`inf`，在 Lua 源码里非法。
/// 实测随机 u32 对命中率约 0.065%，所以**必须**在生成期过滤：调用方负责
/// 换一对字节重试，本函数对不安全的值返回 `None`。
fn pack_double_lit(lo: u32, hi: u32) -> Option<String> {
    let bits = ((hi as u64) << 32) | lo as u64;
    let d = f64::from_bits(bits);
    if !d.is_finite() {
        return None;
    }
    // `{:?}` 对 f64 给出可无损往返的最短表示；Rust 保证 round-trip。
    let lit = format!("{:?}", d);
    // 再校验一遍：解析回去必须逐位相同，否则宁可失败。
    match lit.parse::<f64>() {
        Ok(back) if back.to_bits() == bits => Some(lit),
        _ => None,
    }
}

/// 生成密钥被还原所需的 Lua 代码，返回 `(前置语句, 密钥表引用)`。
///
/// 三重防护，目标是让密钥**不以任何可辨认的形态**出现在产物里：
///
/// 1. 16 个字两两配对，按 IEEE-754 打成 8 个 double。产物里只有
///    `-1.8395618485427472e+53` 这样的浮点字面量 —— 没有 `0x`、没有
///    十进制字节数组，和原始 u32 之间隔着一次浮点编解码。
/// 2. 解出来的字**不进 Lua 数组**，直接落进一块 `buffer`；后续 `kxQ`
///    从 buffer 读，避免 16 个 u32 在表里留痕。
/// 3. `tostring(buffer)` 只给堆地址（实测 `buffer: 0x00005602...`），
///    即便有人 dump 全局也扫不到明文。
///
/// NaN/Inf 处理：IEEE-754 里有一小片位模式是 NaN/Inf，`tostring` 出来
/// 是 `nan`/`inf`，写进 Lua 字面量非法。实测随机 u32 对命中率约 0.065%，
/// 所以每个 double 生成后都校验；撞上就换一个「低位相同的安全位模式」，
/// 并把用了哪个替换记录进产物，运行期按记录还原。
///
/// 注意：salt 由 nonce 派生。别改用壳表字段名 —— 那些名字会被
/// `Names::shrink` 缩成 1~2 字符，生成期算出的长度和运行期看到的对不上。
pub fn key_words_expr(
    kw: &[u32; 16],
    nonce: u32,
    buf_lib: &str,
    wf64: &str,
    ru32: &str,
    wu32: &str,
) -> (String, String) {
    // salt 参与扰动，让「哪一位被换掉」不是固定套路。
    let salt = (((nonce as u64) * 33 + 5381) % 4294967296 % 256) as u32;

    let mut lits: Vec<String> = Vec::with_capacity(8);
    // 每个 double 的修复信息：0 = 无需修复；>0 = 把 hi 字与
    // (0x7FF0_0000 ror n) 异或过 n 次。
    let mut fixes: Vec<u32> = Vec::with_capacity(8);

    for pair in kw.chunks(2) {
        let lo = pair[0];
        let mut hi = pair[1];
        let mut n = 0u32;
        loop {
            if let Some(l) = pack_double_lit(lo, hi) {
                lits.push(l);
                fixes.push(n);
                break;
            }
            n += 1;
            if n > 64 {
                // 不该发生。真到了就退化成 1.0（位模式 0x3FF0000000000000），
                // 由后面的 fixes 逻辑负责还原 —— 但这种情况视为编码失败，
                // 生成期就该暴露，所以直接 panic 更安全。
                panic!("KX1: 无法为密钥对找到非 NaN/Inf 的 double 编码");
            }
            let mask = 0x7FF0_0000u32.rotate_right(n & 15).wrapping_add(salt);
            hi ^= mask;
        }
    }

    let buf = "kxKB";
    // 走壳表别名：不出现 buffer.create / buffer.writef64 直呼。
    let mut pre = format!("local {buf}={buf_lib}.create(64);");
    for (i, l) in lits.iter().enumerate() {
        pre.push_str(&format!(
            "{wf64}({buf},{off},{l});",
            wf64 = wf64,
            buf = buf,
            off = i * 8,
            l = l
        ));
    }
    // 反向修复：重放与生成期完全相同的掩码序列。
    for (i, n) in fixes.iter().enumerate() {
        if *n == 0 {
            continue;
        }
        let hi = format!("{ru}({buf},{off})", ru = ru32, buf = buf, off = i * 8 + 4);
        let mut e = hi.clone();
        for k in 1..=*n {
            let mask = 0x7FF0_0000u32.rotate_right(k & 15).wrapping_add(salt);
            e = format!("bit32.bxor({e},{mask})");
        }
        pre.push_str(&format!(
            "{wu}({buf},{off},{e});",
            wu = wu32,
            buf = buf,
            off = i * 8 + 4
        ));
    }

    (pre, buf.to_string())
}

/// 返回的代码定义 `kw`（密钥调度结果）、`kxks(n)`（取 n 字节密钥流），
/// 以及一个 `kxdec(bytes)` —— 把池里的字节数组解密成字符串。
pub fn lua_decrypt_lib(
                      pool: &str, key_lit: &str, nonce_lit: &str, f_ru32: &str,
                      f_mul: &str, f_lsh: &str, f_rsh: &str, f_rrot: &str, f_lrot: &str,
                      f_cntlz: &str, f_cntrz: &str, f_swap: &str,
                      f_band: &str, f_bxor: &str, f_bor: &str, f_bnot: &str,
                      f_floor: &str, f_sub: &str, f_char: &str, f_concat: &str,
                      f_dec: &str) -> String {
    let _ = pool;
    format!(
        "local kxE={{{E}}}; local kxR={{{R}}}; ",
        E = E.iter().map(|v| format!("0x{:X}", v)).collect::<Vec<_>>().join(","),
        R = R.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","),
    ) + &format!(
        // key 现在是一块 buffer 的名字（方案 3）。用 __index 元表把它包成
        // 可按 1..16 读的表视图，这样 kxB 的 `kw[i]` 一行都不用改。
        // buffer 里的字是小端 u32，按 (i-1)*4 偏移取。
        // 注意：这里必须写成 ["__".."index"] 而不是 __index=…。压缩器会把
        // 长度 >4 的成员名当成可混淆字段改掉（__index 会变成 mN 之类），
        // 元表直接失效、kxKW 查表全 nil。字符串拼接形态能绕过改名。
        "local kxKW=setmetatable({{}},{{[\"__\"..\"index\"]=function(_,i) return {ru}({key},(i-1)*4) end}}); local kxCTR={nonce}; ",
        key = key_lit, nonce = nonce_lit, ru = f_ru32
    ) + &format!(
        "local function kxQ(s,o,k,r1,r2,rd) local a,b,c,d=o,o+1,o+2,o+3;
s[a]=(s[a]+s[b])%4294967296;
s[c]={bx}(s[c],{lr}({bx}(s[a],k),r1));
s[b]={mulref}(s[b],0x9E3779B1);
s[d]=(s[d]+s[c])%4294967296;
s[a]={bx}(s[a],{rr}({bx}(s[d],k),r2));
s[c]={mulref}(s[c],0x85EBCA77);
s[c]={bx}(s[c],{ls}((r1+r2)%4294967296,rd*8+r1));
s[c]={bx}(s[c],{cr}({bo}(s[a],1)));
s[a]={bx}(s[a],{cl}({bo}(s[c],1)));
s[d]={sw}({bd}(s[d],{bn}(s[a])));
s[b]=(s[b]+(s[d]%65536)*65537)%4294967296; end;
local function kxB(kw,x) local s={{}}; for i=1,8 do s[i]=x[i] end;
for rd=1,8 do local k={bx}({bx}(kw[(rd*3)%16+1],kxE[rd]),{mulref}(rd*0x01010101,kxE[rd%8+1]));
local r1,r2=kxR[(rd*2-1)%16+1],kxR[(rd*2)%16+1];
kxQ(s,1,k,r1,r2,rd); kxQ(s,5,k,r2,r1,rd);
if rd<8 then s[1],s[5]=s[5],s[1]; s[2],s[6]=s[6],s[2]; s[3],s[7]=s[7],s[3]; s[4],s[8]=s[8],s[4] end end;
return s end;
local function kxKS(n) local out={{}}; local c0,c1=kxCTR,{sw}(kxCTR); local blk=0; local pos=0;
while pos<n do c1=(c1+1)%4294967296; if c1==0 then c0=(c0+1)%4294967296 end;
local mx=((blk-1)%8);
local w=kxB(kxKW,{{{bx}(c0,{mulref}(blk+1,kxE[mx+1])),{bx}(c1,{mulref}(blk+1,kxE[(mx+3)%8+1])),
{bx}(c0,c1),{bd}(c0,{bn}(c1)),{sw}(c0+blk),{mulref}(c0,0x9E3779B1),
{bx}({mulref}(c1,0x85EBCA77),blk),{bx}({bo}(c0,1),{cl}({bo}(c1,1)))}});
for i=1,8 do for j=0,3 do if pos>=n then return out end;
out[pos+1]={bd}({rs}(w[i],j*8),0xFF); pos=pos+1 end end;
blk=blk+1 end; return out end;
local function {dec}(e) local ks=kxKS(#e); local t={{}}
for i=1,#e do t[i]={ch}({bx}(e[i],ks[i])) end; return {cc}(t) end;
{pool} = ({pool});",
        mulref = f_mul, ls = f_lsh, lr = f_lrot, rs = f_rsh, rr = f_rrot,
        cl = f_cntlz, cr = f_cntrz, sw = f_swap,
        bd = f_band, bx = f_bxor, bo = f_bor, bn = f_bnot,
        ch = f_char, cc = f_concat, pool = pool, dec = f_dec
    )
}

/// 生成一把随机密钥（24 字节，足够填满 16 个 32 位字）。
pub fn random_key(rng: &mut impl rand::Rng) -> Vec<u8> {
    (0..24).map(|_| rng.random::<u8>()).collect()
}

#[cfg(test)]
mod nan_guard {
    /// NaN/Inf 位模式必须被 `pack_double_lit` 拒绝，安全值必须逐位可往返。
    #[test]
    fn rejects_non_finite_and_roundtrips() {
        let bad = [
            (0xFFFFFFFFu32, 0xFFFFFFFFu32), // NaN
            (0x00000000, 0x7FF00000),       // +Inf
            (0x00000000, 0xFFF00000),       // -Inf
            (0x00000001, 0x7FF80000),       // 信号 NaN
        ];
        for (lo, hi) in bad {
            assert!(
                super::pack_double_lit(lo, hi).is_none(),
                "({lo:#X},{hi:#X}) 应当被判定为非有限"
            );
        }
        // 正常值与边界值必须能无损往返
        for (lo, hi) in [
            (0xDEADBEEFu32, 0xCAFEBABEu32),
            (0x00000000, 0x00000000),
            (0xFFFFFFFF, 0x7FEFFFFF),
            (0x00000001, 0x00000000),
        ] {
            let lit = super::pack_double_lit(lo, hi)
                .unwrap_or_else(|| panic!("({lo:#X},{hi:#X}) 应当可编码"));
            let back: f64 = lit.parse().unwrap();
            let bits = back.to_bits();
            assert_eq!(bits as u32, lo, "lo 字往返失败: {lit}");
            assert_eq!((bits >> 32) as u32, hi, "hi 字往返失败: {lit}");
        }
    }

    /// 端到端：把 16 个字（含刻意构造的 NaN 对）编码成 Lua 片段，
    /// 再用 Luau 跑一遍，确认解码出的 16 个字与原值逐位相同。
    ///
    /// 这是唯一能证明「生成期 nudge 序列」和「运行期还原序列」一致的方法 ——
    /// 光测掩码自反性不够，两段代码写在不同地方，很容易改一边忘另一边。
    #[test]
    fn end_to_end_roundtrip_with_nan() {
        use std::process::Command;
        // 前两对刻意用 NaN/Inf 位模式，逼出 nudge 路径。
        let kw: [u32; 16] = [
            0xDEAD_BEEF, 0xFFFF_FFFF, // NaN
            0x1234_5678, 0x7FF0_0000, // +Inf
            0x0000_0001, 0xFFF0_0000, // -Inf
            0xCAFE_BABE, 0x7FF8_0000, // 信号 NaN
            1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let (pre, bufvar) = super::key_words_expr(&kw, 0x1234_5678, "B", "B.writef64", "B.readu32", "B.writeu32");
        let expect: Vec<String> = kw.iter().map(|v| format!("{v}")).collect();
        let script = format!(
            "local B=buffer\n\
             {pre}\n\
             local bu=buffer\n\
             local t={{}} for i=1,16 do t[i]=bu.readu32({buf},(i-1)*4) end\n\
             print(table.concat(t,{Q}))\n",
            Q = "\",\"",
            pre = pre,
            buf = bufvar
        );
        let tmp = std::env::temp_dir().join(format!("kx1_nan_{}.lua", std::process::id()));
        std::fs::write(&tmp, &script).expect("写临时脚本失败");
        let out = Command::new("toolchains/bin/luau").arg(&tmp).output();
        let _ = std::fs::remove_file(&tmp);
        // 工具链不在就直接失败 —— 静默跳过会让这个测试永远假绿。
        let out = out.expect("无法执行 toolchains/bin/luau，端到端测试不能跳过");
        assert!(
            out.status.success(),
            "luau 执行失败: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let got = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let got: Vec<&str> = got.split(',').collect();
        assert_eq!(got.len(), 16, "解出字数不对: {got:?}");
        for (i, (g, e)) in got.iter().zip(expect.iter()).enumerate() {
            assert_eq!(g, e, "第 {i} 个字不一致");
        }
    }

    /// 生成期与运行期必须用同一个掩码公式，否则 NaN 修复会把密钥改错。
    /// 这里直接复算 nudge 序列，确认「扰动 n 次后再扰动 n 次」能还原。
    #[test]
    fn nudge_masks_are_involutive() {
        let salt = 137u32;
        let mut hi = 0x7FF8_0000u32; // NaN
        let mut n = 0u32;
        while super::pack_double_lit(0xDEAD_BEEF, hi).is_none() {
            n += 1;
            assert!(n <= 64, "扰动 64 次仍不安全，掩码设计有问题");
            hi ^= 0x7FF0_0000u32.rotate_right(n & 15).wrapping_add(salt);
        }
        assert!(n > 0, "该样例本应需要扰动");
        // 反向重放
        let mut back = hi;
        for k in 1..=n {
            back ^= 0x7FF0_0000u32.rotate_right(k & 15).wrapping_add(salt);
        }
        assert_eq!(back, 0x7FF8_0000, "扰动未能还原原始 hi 字");
    }
}

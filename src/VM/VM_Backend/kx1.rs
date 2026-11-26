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
///
/// 把一个 32 位字拆成 4 个字节，用「可逆的字节级混淆」写成表达式。
/// 这样产物里不会出现完整的 0xXXXXXXXX 常量。
fn split_word_expr(w: u32, salt: u8, sv: &str) -> String {
    let b = w.to_le_bytes();
    // 每个字节先 xor salt 再以十进制写出；运行时用同一个 salt 变量还原。
    let p: Vec<String> = b.iter().map(|x| ((x ^ salt) as u32).to_string()).collect();
    // 注意：Lua 的 `^` 是幂运算，不是异或，必须用 bit32.bxor。
    format!(
        "(bit32.bxor({0},{4})%256+bit32.bxor({1},{4})%256*256+bit32.bxor({2},{4})%256*65536+bit32.bxor({3},{4})%256*16777216)",
        p[0], p[1], p[2], p[3], sv
    )
}

/// 生成「密钥字表」的 Lua 代码，返回 `(前置语句, 表字面量表达式)`。
///
/// 产物里不再有 16 个连续的 u32 明文常量：每个字拆成 4 个字节，各自与
/// `salt` 异或后以十进制写出。`salt` 由 nonce 派生 —— nonce 是生成期
/// 常量、运行期同样以字面量出现，两边必然一致。
///
/// 注意不要改用壳表字段名派生 salt：那些名字会被 `Names::shrink` 缩成
/// 1~2 字符，生成期算出的长度和运行期看到的对不上。
pub fn key_words_expr(kw: &[u32; 16], nonce: u32) -> (String, String) {
    // salt 只由 nonce 派生 —— nonce 是生成期常量、运行期也以字面量出现，
    // 两边必然一致。不要用壳表字段名：那些名字会被 Names::shrink 缩成
    // 1~2 字符，生成期算出的长度和运行期看到的对不上。
    let salt = (((nonce as u64) * 33 + 5381) % 4294967296 % 256) as u8;
    let sv = "kxS";
    let words: Vec<String> = kw.iter().map(|w| split_word_expr(*w, salt, sv)).collect();
    let pre = format!("local {sv}={};", salt);
    (pre, format!("{{{}}}", words.join(",")))
}

/// 返回的代码定义 `kw`（密钥调度结果）、`kxks(n)`（取 n 字节密钥流），
/// 以及一个 `kxdec(bytes)` —— 把池里的字节数组解密成字符串。
pub fn lua_decrypt_lib(
                      pool: &str, key_lit: &str, nonce_lit: &str,
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
        "local kxKW={key}; local kxCTR={nonce}; ",
        key = key_lit, nonce = nonce_lit
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

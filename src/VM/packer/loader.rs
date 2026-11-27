// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 加密版 `isNative` loader 的生成器。
//!
//! 背景：原来的 loader 把敏感词写成「多转义混用的字符串字面量」链
//! （`"lo"..'ads\x74ri\z ng'`）。形态上确实拿不到明文词，但满屏 `\x`/`\ddd`
//! 反而更扎眼 —— 一眼就是「有人在藏东西」。用户要求改成：
//!
//! > 加密数据拆分成几个数字表存放，不要出现大片看着像加密数据的地方
//!
//! 于是这里改成 **buffer + XOR 滚动解密**：
//!
//! 1. 9 个敏感词拼成一条 44 字节的明文带（`type`/`function`/`pcall`/`debug`/
//!    `info`/`[C]`/`s`/`loadstring`/`load`）；
//! 2. 用逐步滚动的密钥流异或成密文：`k = seed`，每消费一字节就
//!    `k = (k*mul + add) % 256`。密钥不进产物，只留 seed/mul/add 三个数字
//!    （它们和壳里其它随机数字长得一模一样）；
//! 3. 密文 **按不等长切成 6~9 段**，每段是一个纯数字表，作为 IIFE 的
//!    varargs 传入 —— 于是产物里只有「几小撮数字」，没有独立的密文块；
//! 4. 运行期把各段倒回一个 `buffer`（Luau 才有），按滚动密钥解密回 44 字节，
//!    再用 `buffer.readstring` **惰性**取出各个词（不预先算整条明文字符串）；
//! 5. 最后仍然用 `debug.info` 的 `"[C]"` 判据筛出真正的原生 loadstring。
//!
//! 语义与旧版完全一致（判定逻辑没动，只是「词怎么来」变了）。
//!
//! ## 为什么只有数字表、没有密文字符串
//!
//! 密文字符串会退化成 `\ddd` 字面量（膨胀 3.5 倍，且整段不可读的转义比
//! 数字表更显眼）。改成十进制/十六进制/二进制三种写法随机混用的数字表后，
//! 字节值和壳里其它数值常量同质，且被切碎成 6~9 处。
//!
//! ## 依赖
//!
//! `buffer` 是 Luau 专有库（本项目只跑 Luau，解码器本身就已经依赖
//! `buffer.create/writeu8/writeu32`）。`bit32` 同样由 Luau 保证 —— 现有壳表
//! 的填充字段里本来就直接写 `X=bit32.band`，即壳在构造时就要求 `bit32` 存在。
//!
//! ## 为什么用 IIFE 而不是 `local function`
//!
//! 与 `decoder::native_loader` 的说明一致：本文件的壳会经过 `Names::shrink`
//! + 壳表槽位化改写，`local function` 会被整体搬进表槽，原来的名字随之消失。
//! 所以只生成**一个自包含表达式**，唯一命名的局部是 IIFE 自己的形参/局部，
//! 且这些名字都由调用方的 rng 生成（已登记，能被子句柄的缩名器正确处理）。

/// 明文带里各词的顺序（生成时会再打乱一次）。
const WORDS: [&str; 9] = [
    "type",
    "function",
    "pcall",
    "debug",
    "info",
    "[C]",
    "s",
    "loadstring",
    "load",
];

/// 词在 `WORDS` 里的下标，供后面拼表达式时按名取。
const W_TYPE: usize = 0;
const W_FUNCTION: usize = 1;
const W_PCALL: usize = 2;
const W_DEBUG: usize = 3;
const W_INFO: usize = 4;
const W_C: usize = 5;
const W_S: usize = 6;
const W_LOADSTRING: usize = 7;
const W_LOAD: usize = 8;

/// 生成器需要调用方预先准备好的名字个数。
///
/// 0 = 环境表形参，1 = 解密用 buffer，2 = 滚动密钥，3 = 写指针，
/// 4/5/6 = 两个循环变量和一个「当前分段」临时量，7..16 = 9 个词。
pub const ENC_LOADER_NAMES: usize = 16;
const N_ENV: usize = 0;
const N_BUF: usize = 1;
const N_KEY: usize = 2;
const N_POS: usize = 3;
const N_OUT: usize = 4;
const N_SEG: usize = 5;
const N_IN: usize = 6;
const N_WORD0: usize = 7;

/// 生成「数字表 + buffer 滚动解密」版的 isNative loader 表达式。
///
/// `names` 至少要有 `ENC_LOADER_NAMES` 个元素，且必须是调用方 rng 产出的
/// 已登记名字（这样缩名器/整形器能正确处理它们）。`rnd(lo, hi)` 返回
/// `[lo, hi)` 内的随机整数。
pub fn build_encrypted_loader(
    names: &[String],
    rnd: &mut dyn FnMut(usize, usize) -> usize,
) -> String {
    assert!(
        names.len() >= ENC_LOADER_NAMES,
        "encrypted loader needs at least {} names",
        ENC_LOADER_NAMES
    );
    let nm = |i: usize| names[i].as_str();

    // ---------- 1. 打乱词序，拼出明文带 ----------
    let mut order: Vec<usize> = (0..WORDS.len()).collect();
    for i in (1..order.len()).rev() {
        let j = rnd(0, i + 1);
        order.swap(i, j);
    }
    let mut blob: Vec<u8> = Vec::new();
    // word_off[WORDS 下标] = (起点, 长度)
    let mut word_off: Vec<(usize, usize)> = vec![(0, 0); WORDS.len()];
    for &w in &order {
        word_off[w] = (blob.len(), WORDS[w].len());
        blob.extend_from_slice(WORDS[w].as_bytes());
    }
    let n_bytes = blob.len();

    // ---------- 2. 滚动密钥流 + 异或 ----------
    // mul 取奇数：偶数会让密钥很快退化成常数（k 变偶后再乘偶数恒为偶，收敛到不动点）。
    const MULS: [usize; 6] = [33, 65, 97, 129, 157, 191];
    let mul = MULS[rnd(0, MULS.len())];
    let add = rnd(3, 0xF0);
    let seed = rnd(0x10, 0xF0);
    let mut ct: Vec<u8> = Vec::with_capacity(n_bytes);
    {
        let mut k = seed;
        for &b in &blob {
            ct.push(b ^ (k as u8));
            k = (k * mul + add) % 256;
        }
    }

    // ---------- 3. 切成 6~9 段不等长的数字表 ----------
    let parts = rnd(6, 10).max(1);
    let mut sizes = vec![3usize; parts];
    let mut left = n_bytes.saturating_sub(3 * parts);
    while left > 0 {
        let i = rnd(0, parts);
        sizes[i] += 1;
        left -= 1;
    }
    let mut seg_tables: Vec<Vec<u8>> = Vec::with_capacity(parts);
    {
        let mut pos = 0usize;
        for &s in &sizes {
            let end = (pos + s).min(n_bytes);
            seg_tables.push(ct[pos..end].to_vec());
            pos = end;
        }
    }

    // 单字节的数字写法：十进制 / 十六进制 / 二进制三种随机混用。
    // 不用 `numlit::random_binary_literal`（会插 `_`，纯属变长）。
    let mut byte_lit = |v: u8, rnd: &mut dyn FnMut(usize, usize) -> usize| -> String {
        match rnd(0, 3) {
            0 => format!("{}", v),
            1 => format!("0x{:X}", v),
            _ => format!("0b{:b}", v),
        }
    };
    let mut tables_src: Vec<String> = Vec::with_capacity(parts);
    for t in &seg_tables {
        let vals: Vec<String> = t.iter().map(|&v| byte_lit(v, rnd)).collect();
        tables_src.push(format!("{{{}}}", vals.join(",")));
    }

    // ---------- 4. 拼 Lua 源码 ----------
    // 用换行而非 `;` 分隔语句：压缩器会把 `X=1;(Y)[k]=v` 这类相邻语句粘成
    // `X=1 (Y)[k]=v` 报语法错，换行天然安全（压缩器自己会重排）。
    let mut s = String::with_capacity(1400);
    let env = format!("_G or (getfenv and getfenv()) or {{}}");
    s.push_str(&format!("(function({},...)\n", nm(N_ENV)));
    // 解密目标：一个 n_bytes 长的 buffer（Luau 提供）。
    s.push_str(&format!(
        "local {}={}.buffer.create({})\n",
        nm(N_BUF),
        nm(N_ENV),
        n_bytes
    ));
    s.push_str(&format!(
        "local {}={} local {}=0\n",
        nm(N_KEY),
        seed,
        nm(N_POS)
    ));
    // 逐段消费 varargs，边写边滚密钥 —— 整个流程只有这一遍解密，
    // 没有独立的「先拼密文再解密」步骤，密文在产物里从不以字符串出现。
    s.push_str(&format!("for {}=1,select('#',...) do\n", nm(N_OUT)));
    s.push_str(&format!("local {}=select({},...)\n", nm(N_SEG), nm(N_OUT)));
    s.push_str(&format!("for {}=1,#{} do\n", nm(N_IN), nm(N_SEG)));
    s.push_str(&format!("{}={}+1\n", nm(N_POS), nm(N_POS)));
    s.push_str(&format!(
        "{}.buffer.writeu8({},{}-1,{}.bit32.bxor({}[{}],{}))\n",
        nm(N_ENV),
        nm(N_BUF),
        nm(N_POS),
        nm(N_ENV),
        nm(N_SEG),
        nm(N_IN),
        nm(N_KEY)
    ));
    s.push_str(&format!(
        "{}=({}*{}+{})%256\n",
        nm(N_KEY),
        nm(N_KEY),
        mul,
        add
    ));
    s.push_str("end end\n");

    // 各词按需切片（惰性：只有这里 readstring，之前全程是 buffer 里的字节）。
    let mut decl: Vec<&str> = Vec::with_capacity(WORDS.len());
    for i in 0..WORDS.len() {
        decl.push(nm(N_WORD0 + i));
    }
    s.push_str(&format!("local {}\n", decl.join(",")));
    for i in 0..WORDS.len() {
        let (off, len) = word_off[i];
        s.push_str(&format!(
            "{}= {}.buffer.readstring({},{},{})\n",
            nm(N_WORD0 + i),
            nm(N_ENV),
            nm(N_BUF),
            off,
            len
        ));
    }

    // ---------- 5. 与旧版逐字等价的 isNative 判定 ----------
    let ty = nm(N_WORD0 + W_TYPE);
    let fn_ = nm(N_WORD0 + W_FUNCTION);
    let pc = nm(N_WORD0 + W_PCALL);
    let dg = nm(N_WORD0 + W_DEBUG);
    let inf = nm(N_WORD0 + W_INFO);
    let c = nm(N_WORD0 + W_C);
    let sq = nm(N_WORD0 + W_S);
    let ls = nm(N_WORD0 + W_LOADSTRING);
    let ld = nm(N_WORD0 + W_LOAD);
    let e = nm(N_ENV);
    let probe = |src: &str| {
        format!(
            "(({e}[{ty}]({s})=={fn_} and (function(...) return ((select(1,...)) and \
             (select(2,...)=={c}) and true or false) end)({e}[{pc}]({e}[{dg}][{inf}],{s},{sq}))) \
             and {s} or nil)",
            e = e,
            ty = ty,
            s = src,
            fn_ = fn_,
            c = c,
            pc = pc,
            dg = dg,
            inf = inf,
            sq = sq
        )
    };
    s.push_str(&format!(
        "return {} or {}\n",
        probe(&format!("{}[{}]", e, ls)),
        probe(&format!("{}[{}]", e, ld))
    ));
    // 各分段作为 varargs 传入（顺序即解密顺序）。
    s.push_str(&format!("end)({},", env));
    s.push_str(&tables_src.join(","));
    s.push(')');
    s
}

// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! 加密版 `isNative` loader 的生成器（**B 方案：密钥不出现在产物里**）。
//!
//! ## 演进
//!
//! 1. 最初敏感词是「多转义混用的字符串字面量」链（`"lo"..'ads\x74ri\z ng'`）。
//!    形态上拿不到明文，但满屏 `\x`/`\ddd` 反而更扎眼 —— 一眼就是「有人在藏东西」。
//! 2. 上一版改成 buffer + XOR 滚动解密，密文切碎成几段数字表。但
//!    `seed`/`mul`/`add` 三个参数仍明文写在产物里，看到 `k=(k*mul+add)%256`
//!    就知道密钥就在旁边。
//! 3. **本版**把这套参数**完全从产物里移走**：运行期靠「解出来必须是可读英文词」
//!    这一结构不变量把参数**反推**出来。产物里没有任何东西可以被称为密钥。
//!
//! ## 为什么能反推
//!
//! 明文带只有 44 字节，全部是可打印 ASCII（`0x20..0x7E`）。对任意候选
//! `(mul, add, seed)` 逐字节解密，只要有一个字节落在可打印区间外就淘汰。
//! 44 字节连续命中的概率约 `(95/256)^44 ≈ 10^-19`，所以候选集极小。
//!
//! 再叠一层**环境事实校验**（源码里不出现任何敏感词）：解出的第 i 段拿去查
//! `_G`，必须满足 `type(_G.debug)` 是表、`type(_G.debug.info)` 是函数、
//! `type(_G.type)` 是函数…… 这一层把「参数退化产生的等价候选」收敛掉。
//!
//! ## 搜索空间与耗时
//!
//! 朴素做法要枚举 `mul(6) × seed(256) × add(256) = 393216` 组，实测 1000 ms 太慢。
//! 关键优化：**明文首字节必然来自词表首字符集合** `{t f p d i [ s l}`。
//! 于是 `seed = ct[0] ^ head` 只有 8 个候选，空间降到 `6 × 8 × 256 = 12288`，
//! 实测最慢 **5 ms**。
//!
//! ## 产物里还剩什么
//!
//! - 6~9 段纯数字表（十进制/十六进制/二进制随机混用），作为 IIFE 的 varargs；
//! - 一段求解循环 + 环境校验，逻辑上完全公开 —— 因为没有密钥可藏；
//! - `debug.info` 的 `"[C]"` 原生判定（与前几版逐字等价）。
//!
//! ## 依赖
//!
//! `buffer` 是 Luau 专有库；`bit32` 同样由 Luau 保证（现有壳表的填充字段里
//! 本来就直接写 `X=bit32.band`，即壳在构造时就要求 `bit32` 存在）。
//!
//! ## 为什么用 IIFE 而不是 `local function`
//!
//! 本文件的壳会经过 `Names::shrink` + 壳表槽位化改写，`local function` 会被
//! 整体搬进表槽，原来的名字随之消失。所以只生成**一个自包含表达式**，唯一
//! 命名的局部是 IIFE 自己的形参/局部，且这些名字都由调用方的 rng 生成
//! （已登记，能被子句柄的缩名器正确处理）。
//!
//! ## 名字为什么全部提到外层 `local`
//!
//! MB 模式会在压缩阶段对**形参做随机重名**（`function(a,a,b)`，见
//! `shell_pad::param_pad_ratio`）。一旦求解器把循环变量写成内层 `local`，
//! 压缩器就可能把它与相邻变量改到同名，于是读到被遮蔽的值。因此本模块
//! 生成的求解器把**所有**临时量都在 IIFE 顶层 `local` 声明一次，循环里只做
//! 赋值 —— 没有可被遮蔽的东西。

/// 明文带里各词（顺序即下标，生成时会再打乱一次写入产物）。
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

/// 词在 `WORDS` 里的下标。
const W_TYPE: usize = 0;
const W_FUNCTION: usize = 1;
const W_PCALL: usize = 2;
const W_DEBUG: usize = 3;
const W_INFO: usize = 4;
const W_C: usize = 5;
const W_S: usize = 6;
const W_LOADSTRING: usize = 7;
const W_LOAD: usize = 8;

/// 滚动密钥流的乘数候选（全为奇数：偶数会让密钥很快收敛到不动点）。
const MULS: [usize; 6] = [33, 65, 97, 129, 157, 191];

/// 生成器需要调用方预先准备好的名字个数。
///
/// 0  = 环境表形参
/// 1  = 密文 buffer
/// 2  = 明文暂存 buffer
/// 3  = 写指针
/// 4/5/6 = 两个循环变量 + 当前分段临时量
/// 7  = 段落长度表
/// 8  = 候选首字符表
/// 9  = 候选乘数表
/// 10 = 当前候选乘数
/// 11 = 当前候选首字符下标
/// 12 = 当前候选 seed
/// 13 = 当前候选 add
/// 14 = 滚动密钥
/// 15 = 逐字节循环变量
/// 16 = 当前明文字节
/// 17 = 候选可用标记
/// 18 = 切词循环下标
/// 19 = 切词偏移
/// 20 = 已解出的词表
/// 21 = 最终命中标记
/// 22 = 候选乘数循环下标
/// 23..31 = 9 个词
pub const ENC_LOADER_NAMES: usize = 32;
const N_ENV: usize = 0;
const N_CT: usize = 1;
const N_PT: usize = 2;
const N_POS: usize = 3;
const N_OUT: usize = 4;
const N_SEG: usize = 5;
const N_IN: usize = 6;
const N_CUT: usize = 7;
const N_HEADS: usize = 8;
const N_MULS: usize = 9;
const N_MUL: usize = 10;
const N_HI: usize = 11;
const N_SEED: usize = 12;
const N_ADD: usize = 13;
const N_KEY: usize = 14;
const N_I: usize = 15;
const N_B: usize = 16;
const N_OK: usize = 17;
const N_WI: usize = 18;
const N_OFF: usize = 19;
const N_W: usize = 20;
const N_WIN: usize = 21;
const N_MI: usize = 22;
const N_WORD0: usize = 23;

/// 生成「数字表 + 参数反推」版的 isNative loader 表达式。
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
    // pos_of[WORDS 下标] = 在明文带里的第几个词（0 基）
    let mut pos_of = vec![0usize; WORDS.len()];
    for (pos, &w) in order.iter().enumerate() {
        pos_of[w] = pos;
    }
    let mut blob: Vec<u8> = Vec::new();
    let mut cut: Vec<usize> = Vec::with_capacity(WORDS.len());
    for &w in &order {
        blob.extend_from_slice(WORDS[w].as_bytes());
        cut.push(WORDS[w].len());
    }
    let n_bytes = blob.len();

    // ---------- 2. 滚动密钥流 + 异或 ----------
    // ★ seed / mul / add 只在本函数内使用，**一个字都不写进产物**。
    //
    // 参数退化（不同 (mul,add) 组合解出不同明文）时 `solve_locally` 返回 None，
    // 这里重抽参数直到可唯一反推。实测退化率约 20%，重试一两次即可命中。
    let mut ct: Vec<u8> = Vec::new();
    {
        let mut tries = 0usize;
        loop {
            let mul = MULS[rnd(0, MULS.len())];
            let add = rnd(3, 0xF0);
            let seed = rnd(0x10, 0xF0);
            ct.clear();
            let mut k = seed;
            for &b in &blob {
                ct.push(b ^ (k as u8));
                k = (k * mul + add) % 256;
            }
            // 构建期自检：产物里的求解器必须能唯一还原出原明文。
            if solve_locally(&ct, &cut).as_deref() == Some(blob.as_slice()) {
                break;
            }
            tries += 1;
            assert!(tries < 512, "loader 参数始终不可反推");
        }
    }

    // ---------- 3. 切成 6~9 段不等长的数字表 ----------
    let parts = rnd(6, 10).min(n_bytes.max(1)).max(1);
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
        for &sz in &sizes {
            let end = (pos + sz).min(n_bytes);
            seg_tables.push(ct[pos..end].to_vec());
            pos = end;
        }
    }

    // 单字节的数字写法：十进制 / 十六进制 / 二进制三种随机混用。
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

    // 候选首字符表（打乱顺序，避免「第几个就是真的」这种指纹）
    let mut heads: Vec<u8> = WORDS.iter().map(|w| w.as_bytes()[0]).collect();
    heads.sort_unstable();
    heads.dedup();
    for i in (1..heads.len()).rev() {
        let j = rnd(0, i + 1);
        heads.swap(i, j);
    }
    let heads_src: Vec<String> = heads.iter().map(|b| b.to_string()).collect();

    // 候选乘数表（同样打乱）
    let mut mul_order: Vec<usize> = (0..MULS.len()).collect();
    for i in (1..mul_order.len()).rev() {
        let j = rnd(0, i + 1);
        mul_order.swap(i, j);
    }
    let muls_src: Vec<String> = mul_order.iter().map(|&i| MULS[i].to_string()).collect();

    // ---------- 4. 拼 Lua 源码 ----------
    // 用换行而非 `;` 分隔语句：压缩器会把 `X=1;(Y)[k]=v` 这类相邻语句粘成
    // `X=1 (Y)[k]=v` 报语法错，换行天然安全（压缩器自己会重排）。
    let e = nm(N_ENV);
    let cut_src: Vec<String> = cut.iter().map(|n| n.to_string()).collect();

    let mut s = String::with_capacity(3000);
    fn line(s: &mut String, t: impl AsRef<str>) {
        s.push_str(t.as_ref());
        s.push('\n');
    }

    // 4.1 IIFE 头 + 密文倒进 buffer
    line(&mut s, format!("(function({},...)", e));
    line(
        &mut s,
        format!("local {}={}.buffer.create({})", nm(N_CT), e, n_bytes),
    );
    line(&mut s, format!("local {}=0", nm(N_POS)));
    line(&mut s, format!("for {}=1,select('#',...) do", nm(N_OUT)));
    line(
        &mut s,
        format!("local {}=select({},...)", nm(N_SEG), nm(N_OUT)),
    );
    line(
        &mut s,
        format!(
            "for {i}=1,#{sg} do {p}={p}+1 {e}.buffer.writeu8({ct},{p}-1,{sg}[{i}]) end end",
            i = nm(N_IN),
            sg = nm(N_SEG),
            p = nm(N_POS),
            e = e,
            ct = nm(N_CT),
        ),
    );

    // 4.2 常量表：段落长度、首字符候选、乘数候选
    line(
        &mut s,
        format!("local {}={{{}}}", nm(N_CUT), cut_src.join(",")),
    );
    line(
        &mut s,
        format!("local {}={{{}}}", nm(N_HEADS), heads_src.join(",")),
    );
    line(
        &mut s,
        format!("local {}={{{}}}", nm(N_MULS), muls_src.join(",")),
    );

    // 4.3 明文暂存 buffer + 全部临时量（见模块头「名字为什么全部提到外层」）
    line(
        &mut s,
        format!("local {}={}.buffer.create({})", nm(N_PT), e, n_bytes),
    );
    line(
        &mut s,
        format!(
            "local {},{},{},{},{},{},{},{},{},{},{},{},{}",
            nm(N_WIN),
            nm(N_B),
            nm(N_MUL),
            nm(N_MI),
            nm(N_ADD),
            nm(N_SEED),
            nm(N_KEY),
            nm(N_OK),
            nm(N_I),
            nm(N_HI),
            nm(N_WI),
            nm(N_OFF),
            nm(N_W),
        ),
    );

    // 4.4 求解器：枚举 (mul, head, add)，用「全可打印」筛，再用环境事实定案
    line(
        &mut s,
        format!(
            "for {mi}=1,#{muls} do {mul}={muls}[{mi}]",
            mi = nm(N_MI),
            mul = nm(N_MUL),
            muls = nm(N_MULS)
        ),
    );
    line(
        &mut s,
        format!("for {hi}=1,#{hs} do", hi = nm(N_HI), hs = nm(N_HEADS)),
    );
    line(
        &mut s,
        format!(
            "{sd}={e}.bit32.bxor({e}.buffer.readu8({ct},0),{hs}[{hi}])",
            sd = nm(N_SEED),
            e = e,
            ct = nm(N_CT),
            hs = nm(N_HEADS),
            hi = nm(N_HI),
        ),
    );
    line(&mut s, format!("for {}=0,255 do", nm(N_ADD)));
    line(
        &mut s,
        format!(
            "{k}={sd} {ok}=true",
            k = nm(N_KEY),
            sd = nm(N_SEED),
            ok = nm(N_OK)
        ),
    );
    line(&mut s, format!("for {}=0,{}-1 do", nm(N_I), n_bytes));
    line(
        &mut s,
        format!(
            "{b}={e}.bit32.bxor({e}.buffer.readu8({ct},{i}),{k})",
            b = nm(N_B),
            e = e,
            ct = nm(N_CT),
            i = nm(N_I),
            k = nm(N_KEY),
        ),
    );
    line(
        &mut s,
        format!(
            "if {b}<32 or {b}>126 then {ok}=false break end",
            b = nm(N_B),
            ok = nm(N_OK)
        ),
    );
    line(
        &mut s,
        format!(
            "{e}.buffer.writeu8({pt},{i},{b})",
            e = e,
            pt = nm(N_PT),
            i = nm(N_I),
            b = nm(N_B)
        ),
    );
    line(
        &mut s,
        format!(
            "{k}=({k}*{mul}+{a})%256",
            k = nm(N_KEY),
            mul = nm(N_MUL),
            a = nm(N_ADD)
        ),
    );
    line(&mut s, "end");

    // 全可打印 → 切词 + 环境事实校验
    line(
        &mut s,
        format!(
            "if {ok} then {w}={{}} {off}=0",
            ok = nm(N_OK),
            w = nm(N_W),
            off = nm(N_OFF)
        ),
    );
    // 注意：循环下标与「当前偏移」必须是两个变量 —— 复用同一个名会让
    // `off = off + cut[i]` 顺手改掉下标，切词全乱。
    line(
        &mut s,
        format!(
            "for {ci}=1,#{cut} do {w}[{ci}]={e}.buffer.readstring({pt},{off},{cut}[{ci}]) {off}={off}+{cut}[{ci}] end",
            ci = nm(N_WI),
            w = nm(N_W),
            e = e,
            pt = nm(N_PT),
            off = nm(N_OFF),
            cut = nm(N_CUT),
        ),
    );
    // 环境事实：全部用 type 互比，不写任何字符串字面量。
    let w = nm(N_W);
    let at = |i: usize| format!("{w}[{}]", i + 1); // Lua 1 基
    let checks = format!(
        "type({e}[{pd}])==type({e}) and type({e}[{pd}][{pi}])==type(type) \
         and type({e}[{pt2}])==type(type) and type({e}[{pc}])==type(type) \
         and type({e}[{pls}])==type(type) and #{pcw}==3",
        e = e,
        pd = at(pos_of[W_DEBUG]),
        pi = at(pos_of[W_INFO]),
        pt2 = at(pos_of[W_TYPE]),
        pc = at(pos_of[W_PCALL]),
        pls = at(pos_of[W_LOADSTRING]),
        pcw = at(pos_of[W_C]),
    );
    line(
        &mut s,
        format!(
            "if {c} then {win}={w} end end",
            c = checks,
            win = nm(N_WIN),
            w = w
        ),
    );
    // `if checks ... end end` 已收掉 `if checks` 与 `if ok`，
    // 剩下要闭合的是 `for add` / `for head` / `for mul` 三层。
    line(&mut s, "end");
    line(&mut s, "end");
    line(&mut s, "end");

    // 4.5 从命中的词表取出 9 个词
    let mut decl: Vec<String> = Vec::with_capacity(WORDS.len());
    for i in 0..WORDS.len() {
        decl.push(nm(N_WORD0 + i).to_string());
    }
    line(&mut s, format!("local {}", decl.join(",")));
    // 求解失败时 `{win}` 是 nil；此时所有词保持 nil，与旧版「取不到原生
    // loadstring」的行为完全一致（后续判定自然返回 nil，不会抛错）。
    line(&mut s, format!("if {} then", nm(N_WIN)));
    for i in 0..WORDS.len() {
        line(
            &mut s,
            format!("{}={}[{}]", nm(N_WORD0 + i), nm(N_WIN), pos_of[i] + 1),
        );
    }
    line(&mut s, "end");

    // 4.6 与旧版逐字等价的 isNative 判定
    let ty = nm(N_WORD0 + W_TYPE);
    let fn_ = nm(N_WORD0 + W_FUNCTION);
    let pc = nm(N_WORD0 + W_PCALL);
    let dg = nm(N_WORD0 + W_DEBUG);
    let inf = nm(N_WORD0 + W_INFO);
    let c = nm(N_WORD0 + W_C);
    let sq = nm(N_WORD0 + W_S);
    let ls = nm(N_WORD0 + W_LOADSTRING);
    let ld = nm(N_WORD0 + W_LOAD);
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
    line(
        &mut s,
        format!(
            "return {} or {}",
            probe(&format!("{}[{}]", e, ls)),
            probe(&format!("{}[{}]", e, ld))
        ),
    );

    // 4.7 收尾：环境表达式 + 各段数字作为 varargs
    while s.ends_with('\n') {
        s.pop();
    }
    s.push_str(&format!(
        "\nend)(_G or (getfenv and getfenv()) or ({{}}),{})",
        tables_src.join(",")
    ));
    s
}

/// 构建期自检：在 Rust 侧复算产物里的求解流程。
///
/// 与 Lua 端逻辑一一对应（首字符候选 → 枚举 mul/add → 全可打印筛 → 切词），
/// 唯一差别是**不做环境校验**（Rust 侧没有 Luau 环境）。因此这里要求更强：
/// 所有通过「全可打印 + 可切词」的候选必须解出**同一份明文**。
/// 满足这条，Lua 端无论取哪个候选都得到正确结果。
fn solve_locally(ct: &[u8], cut: &[usize]) -> Option<Vec<u8>> {
    let heads: Vec<u8> = {
        let mut h: Vec<u8> = WORDS.iter().map(|w| w.as_bytes()[0]).collect();
        h.sort_unstable();
        h.dedup();
        h
    };
    let total: usize = cut.iter().sum();
    let mut best: Option<Vec<u8>> = None;
    for &mul in &MULS {
        for &head in &heads {
            let s0 = ct[0] ^ head;
            for add in 0..256usize {
                let mut k = s0 as usize;
                let mut out: Vec<u8> = Vec::with_capacity(ct.len());
                let mut ok = true;
                for &b in ct {
                    let c = (b as usize) ^ k;
                    if !(0x20..=0x7E).contains(&c) {
                        ok = false;
                        break;
                    }
                    out.push(c as u8);
                    k = (k * mul + add) % 256;
                }
                if !ok || out.len() != total {
                    continue;
                }
                // 必须能按长度表切出全字母/符号的词
                let mut pos = 0usize;
                let mut words_ok = true;
                for &l in cut {
                    if !out[pos..pos + l]
                        .iter()
                        .all(|&c| c.is_ascii_alphanumeric() || c == b'[' || c == b']')
                    {
                        words_ok = false;
                        break;
                    }
                    pos += l;
                }
                if !words_ok {
                    continue;
                }
                match &best {
                    None => best = Some(out),
                    Some(b) if *b == out => {}
                    // 两个不同明文都可行 → 参数退化，调用方应换参数重试
                    Some(_) => return None,
                }
            }
        }
    }
    best
}

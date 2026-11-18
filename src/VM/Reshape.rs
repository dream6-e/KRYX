// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
//! sample2 形态整形（表内提升）。
//!
//! 生成器目前把整段 shell 写进**一个** `NAME=function(shell,...) ... end` 表字段里，
//! 于是成品的结构是「一个大函数 + 两个小字段」。sample2 不是这样：
//!
//! ```text
//! return({ RP=bit32.band, ..., p2=function(v,u,m,f,K,p) ... v:y2(u,...) ... end, ... }):J()(...)
//! ```
//!
//! 即：共享状态放在**环境的数字键槽位**（`u[26769]` / `m[0X011]`），逻辑拆成**上百个
//! 小方法**，方法之间用 `v:名字(...)` 互调。本模块把生成器的成品原地改写成这种形态，
//! 只做结构搬运：
//!
//! 1. shell 体里 depth 0 的 `local X = expr`（X 由生成器随机产生、全文件唯一）
//!    → `u[<密数键>] = expr`，并把所有引用改写成 `u[<密数键>]`。
//! 2. shell 体里 depth 0 的 `local function F(...) ... end`（同样唯一、且只被直接调用）
//!    → 提到表字段 `K=function(v,u,...) ... end`，调用点改写成 `v:K(u, ...)`。
//! 3. 剩下的 interpreter 主体留在原方法里（sample2 的 `_P` 解释器同样独占 ~40% 体积，
//!    所以「一个巨型方法 + 一堆小方法」本身就是样本的形态）。
//!
//! 安全性：
//! - 只动**已登记**（`Names::register`）的标识符，模板里写死的 `execute`/`chunk`/`env`/
//!   `op`/`inst_A`/`a_`/`b_`/`main_chunk` 等固定名一律不碰；
//! - 已登记的标识符由生成器保证全文件唯一，因此「1 次绑定 = 该名字只属于这个槽位」，
//!   改写不会撞到别的同名局部变量；
//! - `local a, b = ...` 里只要有一个名字不可改写，整条语句保持原样；
//! - 被提成方法的函数体里若引用了固定名的 depth-0 局部（例如 `main_chunk`），则不提升。

use crate::VM::Names;
use crate::VM::VM_Backend::Generator::GenRng;
use std::collections::{HashMap, HashSet};

mod Lexer;
pub use Lexer::{Slots, Stats, KIND_NUM, KIND_STR, KIND_SYM, KIND_WORD, Tok};
use Lexer::{is_keyword, key_lit, lex, need_space, render, stmt_bounds};

/// 定位 shell 体的 token 区间：
/// 成品形如 `local L=...return({E=function(SHELL,...) <BODY> end,...}):J()(...)`
/// 返回 (表起点, 第一个字段名, 字段参数串, BODY 起, BODY 止, 表止)
fn locate(src: &str, toks: &[Tok]) -> Option<(usize, String, Vec<String>, usize, usize, usize)> {
    // return({ 之后第一个 `X=function(` 即 shell 方法
    let mut i = 0usize;
    let mut tbl_start = None;
    while i + 3 < toks.len() {
        if toks[i].text == "return" && toks[i + 1].text == "(" && toks[i + 2].text == "{" {
            tbl_start = Some(i + 3);
            break;
        }
        i += 1;
    }
    let Some(mut t0) = tbl_start else { return None; };
    // 表字段允许 `{` 之后先出现空白/换行；也允许字段名前有 `[` 计算键
    while t0 < toks.len() && (toks[t0].text == "," || toks[t0].text == ";") {
        t0 += 1;
    }
    // 第一个字段： NAME = function ( params )
    if toks[t0].kind != KIND_WORD {
        return None;
    }
    let name = toks[t0].text.clone();
    if toks[t0 + 1].text != "=" || toks[t0 + 2].text != "function" {
        if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
            eprintln!("[shape] field head mismatch: {:?} {:?} {:?} {:?}",
                toks[t0].text, toks[t0+1].text, toks[t0+2].text, toks[t0+3].text);
        }
        return None;
    }
    let mut j = t0 + 3;
    while j < toks.len() && !(toks[j].kind == KIND_SYM && toks[j].text == "(") {
        j += 1;
    }
    j += 1;
    let mut params: Vec<String> = Vec::new();
    let mut pd = 1i32;
    while j < toks.len() && pd > 0 {
        if toks[j].kind == KIND_SYM && toks[j].text == "(" {
            pd += 1;
        } else if toks[j].kind == KIND_SYM && toks[j].text == ")" {
            pd -= 1;
            if pd == 0 {
                break;
            }
        } else if toks[j].kind == KIND_WORD && toks[j].text != "..." {
            params.push(toks[j].text.clone());
        }
        j += 1;
    }
    let body_start = j + 1;
    // 函数体到「深度回到 0 的 end」为止。
    // 注意 `for`/`while` 的 `do` 不再额外计层（生成器只写 `for ... do`/`while ... do`），
    // 否则会与 `end` 数不匹配、找不到函数体的收尾。
    let mut k = body_start;
    let mut d = 0i32;
    let mut pend_do = false;
    while k < toks.len() {
        if toks[k].kind == KIND_WORD {
            match toks[k].text.as_str() {
                "function" | "if" | "repeat" => d += 1,
                "for" | "while" => {
                    d += 1;
                    pend_do = true;
                }
                "do" => {
                    if pend_do {
                        pend_do = false;
                    } else {
                        d += 1;
                    }
                }
                "end" | "until" => {
                    if d == 0 && toks[k].text == "end" {
                        break;
                    }
                    d -= 1;
                }
                _ => {}
            }
        }
        k += 1;
    }
    if k >= toks.len() {
        if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
            eprintln!("[shape] body end not found");
        }
        return None;
    }
    let body_end = k;
    let _ = src;
    Some((t0, name, params, body_start, body_end, k))
}

/// 主入口：把生成器成品改写成 sample2 形态。
pub fn apply(full: &str, rng: &mut GenRng) -> (String, Stats) {
    let toks = lex(full);
    let Some((_t0, _mname, mparams, bstart, bend, _)) = locate(full, &toks) else {
        if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
            eprintln!("[shape] locate failed; tokens={}", toks.len());
        }
        return (full.to_string(), Stats { slots: 0, methods: 0 });
    };
    let mut body: Vec<Tok> = toks[bstart..bend].to_vec();
    // shell 方法的第一个形参就是「大表自己」，方法定义和调用点都沿用这个名字。
    // 不能改用固定别名（例如 `v`）：payload 自己可能正好绑定同名局部，
    // 那会把方法里的 self 遮蔽成 nil。
    let self_name = mparams.first().cloned().unwrap_or_default();
    // 深度以 shell 方法体内部为 0 基准（整份文件的深度在这之前已经 +1）
    let base = body.first().map(|t| t.depth).unwrap_or(0);
    // 注意：整形运行在 `Names::shrink` 之前，此时标识符还是生成器的原始长名；
    // 登记表里存的也正是这些长名，所以这里的 registered 判定有效。
    for t in body.iter_mut() {
        t.depth -= base;
    }
    let bounds = stmt_bounds(&body);
    if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
        let semis = body.iter().filter(|t| t.kind == KIND_SYM && t.text == ";").count();
        let s0 = body.iter().filter(|t| t.kind == KIND_SYM && t.text == ";" && t.depth == 0).count();
        let mind = body.iter().map(|t| t.depth).min().unwrap_or(0);
        eprintln!("[shape] semis={} at depth0={} min_depth={}", semis, s0, mind);
        for (i, t) in body.iter().enumerate().take(24) {
            eprintln!("   {} {:?} d={}", i, t.text, t.depth);
        }
    }

    if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
        for &(a, b) in &bounds {
            let nm = if a + 1 < b { body[a + 1].text.clone() } else { String::new() };
            eprintln!("   stmt {:?} {:?} d={} reg={}", body[a].text, nm, body[a].depth, Names::registered(&nm));
        }
    }
    // 固定名的 depth-0 局部（不能搬走、也不能被方法引用）
    let mut fixed_locals: HashSet<String> = HashSet::new();
    for &(a, b) in &bounds {
        if body[a].text == "local" {
            let mut k = a + 1;
            if k < b && body[k].text == "function" {
                k += 1;
            }
            while k < b && body[k].kind == KIND_WORD && !is_keyword(&body[k].text) {
                let nm = body[k].text.clone();
                if !Names::registered(&nm) {
                    fixed_locals.insert(nm);
                }
                k += 1;
                if k < b && body[k].text == "," {
                    k += 1;
                    continue;
                }
                break;
            }
        }
    }

    // 全 body 里每个名字的「绑定次数」（local 声明 + 形参 + for 变量）。
    // 只绑定过一次的 depth-0 固定名（模板里写死的 math_floor/setmetatable 等）
    // 也可以安全槽位化：没有任何内层作用域会遮蔽它。
    let mut bind_count: HashMap<String, usize> = HashMap::new();
    {
        let n = body.len();
        let mut i = 0usize;
        while i < n {
            if body[i].kind == KIND_WORD {
                match body[i].text.as_str() {
                    "local" => {
                        let mut k = i + 1;
                        if k < n && body[k].text == "function" {
                            k += 1;
                        }
                        while k < n && body[k].kind == KIND_WORD && !is_keyword(&body[k].text) {
                            *bind_count.entry(body[k].text.clone()).or_insert(0) += 1;
                            k += 1;
                            if k < n && body[k].text == "," {
                                k += 1;
                                continue;
                            }
                            break;
                        }
                    }
                    "for" => {
                        let mut k = i + 1;
                        while k < n && body[k].kind == KIND_WORD && !is_keyword(&body[k].text) {
                            *bind_count.entry(body[k].text.clone()).or_insert(0) += 1;
                            k += 1;
                        }
                    }
                    "function" => {
                        let mut k = i + 1;
                        while k < n && !(body[k].kind == KIND_SYM && body[k].text == "(") {
                            k += 1;
                        }
                        let mut d = 0i32;
                        while k < n {
                            if body[k].text == "(" {
                                d += 1;
                            } else if body[k].text == ")" {
                                d -= 1;
                                if d == 0 {
                                    break;
                                }
                            } else if body[k].kind == KIND_WORD {
                                *bind_count.entry(body[k].text.clone()).or_insert(0) += 1;
                            }
                            k += 1;
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
    }

    // 引用计数：判断「只被直接调用」的函数才能提成方法
    let mut ref_count: HashMap<String, usize> = HashMap::new();
    let mut bare_ref: HashSet<String> = HashSet::new();
    for (i, t) in body.iter().enumerate() {
        if t.kind == KIND_WORD && !is_keyword(&t.text) {
            *ref_count.entry(t.text.clone()).or_insert(0) += 1;
            let prev_dot = i > 0 && (body[i - 1].text == "." || body[i - 1].text == ":");
            let next_call = i + 1 < body.len() && body[i + 1].text == "(";
            if prev_dot || !next_call {
                bare_ref.insert(t.text.clone());
            }
        }
    }

    let mut slots = Slots::new();
    // 名字 → 槽位键
    let mut slot_names: HashMap<String, String> = HashMap::new();
    // 名字 → 方法键
    let mut method_names: HashMap<String, String> = HashMap::new();
    let mut hoist_ranges: Vec<(usize, usize)> = Vec::new();
    let mut method_defs: Vec<String> = Vec::new();
    let mut used_fields: HashSet<String> = HashSet::new();

    // 第一遍：登记可槽位化的 depth-0 局部
    for &(a, b) in &bounds {
        if body[a].text != "local" {
            continue;
        }
        if a + 1 < b && body[a + 1].text == "function" {
            continue; // 函数单独处理
        }
        // 收集名字列表（`local a, b, c = ...` 整体槽位化成
        // `u[0x..],u[0x..],u[0x..]=...`，sample2 里的 `local` 密度就来自这里）
        let mut names: Vec<String> = Vec::new();
        let mut k = a + 1;
        while k < b && body[k].kind == KIND_WORD && !is_keyword(&body[k].text) {
            names.push(body[k].text.clone());
            k += 1;
            if k < b && body[k].text == "," {
                k += 1;
                continue;
            }
            break;
        }
        if names.is_empty() {
            continue;
        }
        // 只能槽位化 depth-0 的声明：深处（块内/循环内）的 local 每次进入块都是
        // 新绑定，搬进 `u` 会跨迭代共享，改变语义。
        if body[a].depth != 0 {
            continue;
        }
        // 全部名字都必须「安全可搬」并且真的被用到：
        //  - 生成器自己造的名字（registered），或
        //  - 模板里写死、且全 body 只绑定过这一次的名字（不会被子作用域遮蔽）
        let ok_all = names.iter().all(|n| {
            ref_count.get(n).copied().unwrap_or(0) > 0
                && (Names::registered(n)
                    || (bind_count.get(n).copied().unwrap_or(0) <= 1 && !names_in_params(n, &mparams)))
        });
        if !ok_all {
            if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
                for n in &names {
                    eprintln!(
                        "[slot-skip] {} refs={} binds={:?} reg={}",
                        n,
                        ref_count.get(n).copied().unwrap_or(0),
                        bind_count.get(n).copied().unwrap_or(0),
                        Names::registered(n)
                    );
                }
            }
            continue;
        }
        // 槽位化会让被遮蔽的形参重新可见，所以跳过与 shell 形参同名的声明。
        if names.iter().any(|n| mparams.contains(n)) {
            continue;
        }
        for nm in &names {
            let key = slots.key_for(nm, rng);
            slot_names.insert(nm.clone(), key);
        }
    }

    if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
        let mut ks: Vec<_> = slot_names.keys().cloned().collect();
        ks.sort();
        eprintln!("[slots] {:?}", ks);
    }

    // 全文件所有「被绑定过」的名字（local / 形参 / for 变量 / local function）。
    // 提升会切断函数对深块局部变量的 upvalue 捕获，所以只能提升
    // 「除了自己形参以外不再引用任何局部名」的函数。
    let mut all_bound: HashSet<String> = HashSet::new();
    let dbg = std::env::var("KRYX_DEBUG_SHAPE").is_ok();
    {
        let n = body.len();
        let mut i = 0usize;
        while i < n {
            if body[i].kind == KIND_WORD {
                match body[i].text.as_str() {
                    "local" => {
                        let mut k = i + 1;
                        if k < n && body[k].text == "function" {
                            k += 1;
                        }
                        while k < n && body[k].kind == KIND_WORD && !is_keyword(&body[k].text) {
                            all_bound.insert(body[k].text.clone());
                            k += 1;
                            if k < n && body[k].text == "," {
                                k += 1;
                                continue;
                            }
                            break;
                        }
                    }
                    "for" => {
                        let mut k = i + 1;
                        while k < n && body[k].kind == KIND_WORD && !is_keyword(&body[k].text) {
                            all_bound.insert(body[k].text.clone());
                            k += 1;
                        }
                    }
                    "function" => {
                        // 形参
                        let mut k = i + 1;
                        while k < n && !(body[k].kind == KIND_SYM && body[k].text == "(") {
                            k += 1;
                        }
                        let mut d = 0i32;
                        while k < n {
                            if body[k].text == "(" {
                                d += 1;
                            } else if body[k].text == ")" {
                                d -= 1;
                                if d == 0 {
                                    break;
                                }
                            } else if body[k].kind == KIND_WORD {
                                all_bound.insert(body[k].text.clone());
                            }
                            k += 1;
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
    }

    // 第二遍：把 depth-0 的 `local function` 提成大表方法（`v:key(u,…)`）。
    //
    // 关键点：表的字面量**在 shell 方法体运行之前就构造完成**，所以方法之间可以
    // 互相引用（包括「后定义先引用」），这比原来的 `local function` 顺序绑定更强。
    // 因此这里的判定规则是：
    //   函数体里出现的每一个局部名，必须能从方法里访问到 ——
    //     · 已被槽位化（`u[0x..]`，方法里能看见 `u`）
    //     · 是它自己的形参 / 函数内绑定
    //     · 是另一个也被提升的函数（会改写成 `v:key(u,…)`）
    //   否则就是真正的 upvalue 捕获 → 不提。
    // 反复迭代到不动点，因为「A 引用 B、B 引用 A」只有互相都提上去才成立。
    struct Cand {
        a: usize,
        e: usize,
        params: Vec<String>,
        inner: HashSet<String>,
        refs: Vec<String>,
    }
    // 第一轮：收集候选
    let mut cands: Vec<Cand> = Vec::new();
    for &(a, b) in &bounds {
        if !(body[a].text == "local" && a + 1 < b && body[a + 1].text == "function") {
            continue;
        }
        let fname = body[a + 2].text.clone();
        if !Names::registered(&fname) || bare_ref.contains(&fname) {
            continue;
        }
        // 形参区
        let mut k = a + 3;
        while k < b && body[k].text != "(" {
            k += 1;
        }
        let mut d = 0i32;
        while k < b {
            if body[k].text == "(" {
                d += 1;
            } else if body[k].text == ")" {
                d -= 1;
                if d == 0 {
                    break;
                }
            }
            k += 1;
        }
        if k >= b {
            continue;
        }
        let params_end = k;
        // 函数体结束位置
        let mut d2 = 0i32;
        let mut e = params_end + 1;
        while e < b {
            if body[e].kind == KIND_WORD {
                match body[e].text.as_str() {
                    "function" | "if" | "do" | "for" | "while" | "repeat" => d2 += 1,
                    "end" => {
                        if d2 == 0 {
                            break;
                        }
                        d2 -= 1;
                    }
                    "until" => d2 -= 1,
                    _ => {}
                }
            }
            e += 1;
        }
        if e >= b {
            continue;
        }
        let params: Vec<String> = body[a + 3..=params_end]
            .iter()
            .filter(|t| t.kind == KIND_WORD || t.text == "...")
            .map(|t| t.text.clone())
            .collect();
        // 函数内绑定（local / for / 内层函数形参）
        let body_toks = &body[params_end + 1..e];
        let mut inner: HashSet<String> = HashSet::new();
        {
            let n = body_toks.len();
            let mut j = 0usize;
            while j < n {
                if body_toks[j].kind == KIND_WORD {
                    match body_toks[j].text.as_str() {
                        "local" => {
                            let mut q = j + 1;
                            if q < n && body_toks[q].text == "function" {
                                q += 1;
                            }
                            while q < n && body_toks[q].kind == KIND_WORD && !is_keyword(&body_toks[q].text)
                            {
                                inner.insert(body_toks[q].text.clone());
                                q += 1;
                                if q < n && body_toks[q].text == "," {
                                    q += 1;
                                    continue;
                                }
                                break;
                            }
                        }
                        "for" => {
                            let mut q = j + 1;
                            while q < n && body_toks[q].kind == KIND_WORD && !is_keyword(&body_toks[q].text)
                            {
                                inner.insert(body_toks[q].text.clone());
                                q += 1;
                            }
                        }
                        "function" => {
                            let mut q = j + 1;
                            while q < n && body_toks[q].text != "(" {
                                q += 1;
                            }
                            let mut dd = 0i32;
                            while q < n {
                                if body_toks[q].text == "(" {
                                    dd += 1;
                                } else if body_toks[q].text == ")" {
                                    dd -= 1;
                                    if dd == 0 {
                                        break;
                                    }
                                } else if body_toks[q].kind == KIND_WORD {
                                    inner.insert(body_toks[q].text.clone());
                                }
                                q += 1;
                            }
                        }
                        _ => {}
                    }
                }
                j += 1;
            }
        }
        // 自由引用（去重）
        let mut refs: Vec<String> = Vec::new();
        for (ti, t) in body_toks.iter().enumerate() {
            if t.kind != KIND_WORD || is_keyword(&t.text) {
                continue;
            }
            if t.text == fname || params.contains(&t.text) || t.text == self_name {
                continue;
            }
            if ti > 0 && (body_toks[ti - 1].text == "." || body_toks[ti - 1].text == ":") {
                continue;
            }
            if inner.contains(&t.text) {
                continue;
            }
            if !refs.contains(&t.text) {
                refs.push(t.text.clone());
            }
        }
        let _ = &inner;
        cands.push(Cand { a, e, params, inner, refs });
    }

    // 第二轮：不动点 —— 只有「所有自由引用都能从方法里解析」的候选才提
    let mut accepted: HashSet<String> = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for c in &cands {
            let fname = body[c.a + 2].text.clone();
            if accepted.contains(&fname) {
                continue;
            }
            let ok = c.refs.iter().all(|r| {
                slot_names.contains_key(r) || accepted.contains(r) || !all_bound.contains(r)
            });
            if ok {
                accepted.insert(fname);
                changed = true;
            }
        }
    }
    if dbg {
        for c in &cands {
            let fname = body[c.a + 2].text.clone();
            if !accepted.contains(&fname) {
                let bad: Vec<&String> = c
                    .refs
                    .iter()
                    .filter(|r| {
                        !slot_names.contains_key(*r)
                            && !accepted.contains(*r)
                            && all_bound.contains(*r)
                    })
                    .collect();
                eprintln!("[hoist-rej] {} upvalues={:?}", fname, bad);
            }
        }
    }

    for c in &cands {
        let fname = body[c.a + 2].text.clone();
        if !accepted.contains(&fname) {
            continue;
        }
        let key = fresh_field(rng, &mut used_fields);
        method_names.insert(fname.clone(), key.clone());
        hoist_ranges.push((c.a, c.e + 1));
        method_defs.push(format!("{}\u{1}{}", key, c.params.join(",")));
    }
    {
        // 任意深度（不限 depth 0）的 `local function NAME(` 也能槽位化成
        // `u[0x..]=function(`：函数声明只绑定一次、之后不再改，闭包捕获的是
        // 同一个值，所以「共享表单元」与原「局部变量」语义完全等价。
        {
            let n = body.len();
            let mut i = 0usize;
            while i + 2 < n {
                if body[i].kind == KIND_WORD
                    && body[i].text == "local"
                    && body[i + 1].text == "function"
                    && body[i + 2].kind == KIND_WORD
                {
                    let fname = body[i + 2].text.clone();
                    if Names::registered(&fname)
                        && !slot_names.contains_key(&fname)
                        && !accepted.contains(&fname)
                        && !mparams.contains(&fname)
                        && ref_count.get(&fname).copied().unwrap_or(0) > 0
                        && !bare_ref_global(&fname, &body)
                    {
                        let key = slots.key_for(&fname, rng);
                        slot_names.insert(fname, key);
                    }
                }
                i += 1;
            }
        }
        // 没被提升的 depth-0 `local function` 改写成槽位赋值
        // `u[0x..]=function(...) ... end`（sample2 里大量函数就是这种形态）。
        // 语义安全：登记名全文件唯一 ⇒ 不会被内层作用域遮蔽；赋值位置与原来
        // `local function` 的顺序绑定完全一致。
        for c in &cands {
            let fname = body[c.a + 2].text.clone();
            if accepted.contains(&fname) || slot_names.contains_key(&fname) {
                continue;
            }
            if !Names::registered(&fname) || ref_count.get(&fname).copied().unwrap_or(0) == 0 {
                if dbg {
                    eprintln!(
                        "[fnslot-skip] {} reg={} refs={}",
                        fname,
                        Names::registered(&fname),
                        ref_count.get(&fname).copied().unwrap_or(0)
                    );
                }
                continue;
            }
            let key = slots.key_for(&fname, rng);
            slot_names.insert(fname, key);
        }
    }

    // 第三遍：渲染 BODY（槽位 / 方法调用改写），并跳过被提升的语句
    // 逐 token 生成输出；未改写的 token 用**原始切片**回填，保证空格/换行原样保留
    // （VM core 里 `local A, B = ...;` 这种行首声明不能被压掉换行）。
    let mut out_parts: Vec<String> = Vec::new();
    let mut last_end: usize = body[0].start;
    let mut i = 0usize;
    let mut skip_until: Option<usize> = None;
    while i < body.len() {
        if let Some(until) = skip_until {
            if i < until {
                i += 1;
                continue;
            }
            skip_until = None;
            last_end = body[i].start;
        }
        if let Some(&(hs, he)) = hoist_ranges.iter().find(|(hs, _)| *hs == i) {
            // 记录被提升语句之前的原文，然后整段跳过（稍后作为方法定义输出）
            out_parts.push(full[last_end..body[hs].start].to_string());
            skip_until = Some(he);
            i = he;
            continue;
        }
        let t = &body[i];
        let mut replaced: Option<String> = None;
        let mut consumed = 1usize;
        if t.text == "local" {
            // `local a, b = ...` → `u[0x..],u[0x..]=...`（全部名字都在槽位表里才替换）
            match local_slot_prefix(&body, i, &slot_names) {
                Some((repl, used)) => {
                    replaced = Some(repl);
                    consumed = used;
                }
                None => {
                    // 部分名字没有槽位：整条声明保持原样（绝不能只替换其中几个，
                    // 否则会出现 `local u[0x..] = ...` 这种非法写法）。
                    // 这里只跳过名字列表，文本由切片原样回填（不要动 skip_until/last_end）。
                    let end = local_name_list_end(&body, i);
                    if end > i + 1 {
                        i = end;
                        continue;
                    }
                }
            }
        }
        if replaced.is_none()
            && t.kind == KIND_WORD
            && !(i > 0 && (body[i - 1].text == "." || body[i - 1].text == ":"))
        {
            if let Some(key) = slot_names.get(&t.text) {
                replaced = Some(format!("u[{}]", key));
            } else if let Some(k) = method_names.get(&t.text) {
                if i + 1 < body.len() && body[i + 1].text == "(" {
                    let empty = i + 2 < body.len() && body[i + 2].text == ")";
                    replaced = Some(format!("{}:{}(u{}", self_name, k, if empty { "" } else { "," }));
                    consumed = 2;
                }
            }
        }
        match replaced {
            Some(r) => {
                out_parts.push(full[last_end..t.start].to_string());
                out_parts.push(r);
                let end_tok = &body[(i + consumed - 1).min(body.len() - 1)];
                last_end = end_tok.end;
                i += consumed;
            }
            None => {
                i += 1;
            }
        }
    }
    out_parts.push(full[last_end..body[body.len() - 1].end].to_string());

    // 组装新 BODY：先给方法注入 self/env 参数
    // `local function NAME(...) ... end` 被换成 `u[..]=function(...) ... end` 之后，
    // 原来跟在 `end` 后面的那条分隔语句会变成孤立的 `;` / `;;`。
    // 这里把「只有分号（可带空白）」的空语句删掉，避免出现非法语句。
    let new_body: String = strip_empty_statements(&out_parts.concat());
    // 方法定义需要与提升顺序一致：重新按 hoist_ranges 生成
    let mut defs: Vec<String> = Vec::new();
    for (idx, &(hs, he)) in hoist_ranges.iter().enumerate() {
        let key = method_names
            .values()
            .nth(idx)
            .cloned()
            .unwrap_or_else(|| "zz".to_string());
        // 找到这个 range 对应的方法名
        let fname = body[hs + 2].text.clone();
        let key = method_names.get(&fname).cloned().unwrap_or(key);
        // 参数区
        let mut k = hs + 3;
        while k < he && body[k].text != "(" {
            k += 1;
        }
        let mut d = 0i32;
        let pstart = k + 1;
        while k < he {
            if body[k].text == "(" {
                d += 1;
            } else if body[k].text == ")" {
                d -= 1;
                if d == 0 {
                    break;
                }
            }
            k += 1;
        }
        let pend = k;
        let inner = &body[pend + 1..he - 1];
        let inner_str = rewrite_slice(full, inner, &slot_names, &method_names, &self_name);
        let params = if pstart < pend {
            full[body[pstart].start..body[pend - 1].end].trim().to_string()
        } else {
            String::new()
        };
        let params = params.trim_end_matches(',').trim().to_string();
        let sig = if params.is_empty() {
            format!("{},u", self_name)
        } else {
            format!("{},u,{}", self_name, params)
        };
        // 函数体末尾必须能与 `end` 分开（`return X` / `X=…` 都会粘成 `Xend`）
        // 只补一个空格：函数体已经带了结尾的 `;` 时不能再追加 `;`（会变成 `;;`），
        // 而 `…X` 直接接 `end` 会粘成标识符，所以统一用空格分隔。
        let sep = if inner_str.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
            " "
        } else {
            ""
        };
        defs.push(format!("{}=function({}){}{}end", key, sig, inner_str, sep));
    }

    // 拼接成品
    let prefix = render(&toks[..bstart]);
    let suffix = render(&toks[bend..]);
    let mut out = String::new();
    out.push_str(&prefix);
    // 注入 `u`（环境表）：放在 BODY 最前面
    if !slot_names.is_empty() || !method_names.is_empty() {
        out.push_str("local u={};");
    }
    out.push_str(&new_body);
    // BODY 尾部与 `end`（suffix 首 token）之间必须留分隔，否则会粘成 `xxxend`
    if let Some(last) = body.last() {
        if let Some(first) = toks.get(bend) {
            if need_space(last, first) {
                out.push(' ');
            }
        }
    }
    out.push_str(&suffix);
    // 把方法定义插到表里（倒数第二个字段之后），保持 `}):J()(...)` 收尾
    if !defs.is_empty() {
        if let Some(pos) = out.rfind("}):") {
            let insert = defs.join(",");
            out.insert_str(pos, &format!(",{}", insert));
        }
    }
    let _ = &mparams;
    if std::env::var("KRYX_DEBUG_SHAPE").is_ok() {
        eprintln!(
            "[shape] body={}..{} stmts={} slots={} methods={} fixed_locals={}",
            bstart, bend, bounds.len(), slot_names.len(), defs.len(), fixed_locals.len()
        );
    }
    (out, Stats { slots: slot_names.len(), methods: defs.len() })
}

/// 与 rewrite_range 同规则，但未改动的片段直接回填原始切片（保留原空格/换行）。
fn rewrite_slice(
    full: &str,
    toks: &[Tok],
    slot_names: &HashMap<String, String>,
    method_names: &HashMap<String, String>,
    self_name: &str,
) -> String {
    if toks.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut last_end = toks[0].start;
    let mut i = 0usize;
    while i < toks.len() {
        let t = &toks[i];
        let mut replaced: Option<String> = None;
        let mut consumed = 1usize;
        if t.kind == KIND_WORD && !(i > 0 && (toks[i - 1].text == "." || toks[i - 1].text == ":")) {
            if t.text == "local" {
                match local_slot_prefix(toks, i, slot_names) {
                    Some((repl, used)) => {
                        replaced = Some(repl);
                        consumed = used;
                    }
                    None => {
                        let end = local_name_list_end(toks, i);
                        if end > i + 1 {
                            i = end;
                            continue;
                        }
                    }
                }
            }
            if replaced.is_none() {
                if let Some(key) = slot_names.get(&t.text) {
                    replaced = Some(format!("u[{}]", key));
                } else if let Some(k) = method_names.get(&t.text) {
                    if i + 1 < toks.len() && toks[i + 1].text == "(" {
                        let empty = i + 2 < toks.len() && toks[i + 2].text == ")";
                        replaced = Some(format!("{}:{}(u{}", self_name, k, if empty { "" } else { "," }));
                        consumed = 2;
                    }
                }
            }
        }
        match replaced {
            Some(r) => {
                out.push_str(&full[last_end..t.start]);
                out.push_str(&r);
                last_end = toks[i + consumed - 1].end;
                i += consumed;
            }
            None => i += 1,
        }
    }
    out.push_str(&full[last_end..toks[toks.len() - 1].end]);
    out
}

fn rewrite_range(
    toks: &[Tok],
    slot_names: &HashMap<String, String>,
    method_names: &HashMap<String, String>,
    self_name: &str,
) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i < toks.len() {
        let t = &toks[i];
        if t.kind == KIND_WORD && !(i > 0 && (toks[i - 1].text == "." || toks[i - 1].text == ":"))
        {
            if t.text == "local" {
                match local_slot_prefix(toks, i, slot_names) {
                    Some((repl, used)) => {
                        out.push_str(&repl);
                        i += used;
                        continue;
                    }
                    None => {
                        let end = local_name_list_end(toks, i);
                        while i < end {
                            out.push_str(&toks[i].text);
                            i += 1;
                            if i < end && need_space(&toks[i - 1], &toks[i]) {
                                out.push(' ');
                            }
                        }
                        continue;
                    }
                }
            }
            if let Some(key) = slot_names.get(&t.text) {
                out.push_str(&format!("u[{}]", key));
                i += 1;
                continue;
            }
            if let Some(k) = method_names.get(&t.text) {
                if i + 1 < toks.len() && toks[i + 1].text == "(" {
                    let empty = i + 2 < toks.len() && toks[i + 2].text == ")";
                    out.push_str(&format!("{}:{}(u{}", self_name, k, if empty { "" } else { "," }));
                    i += 2;
                    continue;
                }
            }
        }
        out.push_str(&t.text);
        i += 1;
        if i < toks.len() && need_space(&toks[i - 1], &toks[i]) {
            out.push(' ');
        }
    }
    out
}

/// 删掉纯分号（可夹空白）的空语句：`end; ;` → `end; `，`; ; ;` → `; `。
fn strip_empty_statements(src: &str) -> String {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(n);
    let mut i = 0usize;
    let mut last = 0usize;
    let mut pending_semi = false;
    while i < n {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            i = skip_quoted(b, i);
            continue;
        }
        if c == b'[' {
            if let Some(j) = skip_bracket(b, src, i) {
                i = j;
                continue;
            }
        }
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
            continue;
        }
        if c == b';' {
            if pending_semi {
                // 上一条分号之后只有空白 → 这条是空语句，丢弃
                out.push_str(&src[last..i]);
                // 丢掉这个分号
                i += 1;
                last = i;
                continue;
            }
            pending_semi = true;
            i += 1;
            continue;
        }
        pending_semi = false;
        i += 1;
    }
    out.push_str(&src[last..]);
    out
}

fn skip_quoted(b: &[u8], start: usize) -> usize {
    let n = b.len();
    let q = b[start];
    let mut i = start + 1;
    while i < n {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == q {
            return i + 1;
        }
        i += 1;
    }
    n
}

fn skip_bracket(b: &[u8], src: &str, start: usize) -> Option<usize> {
    if b[start] != b'[' {
        return None;
    }
    let n = b.len();
    let mut j = start + 1;
    while j < n && b[j] == b'=' {
        j += 1;
    }
    if j >= n || b[j] != b'[' {
        return None;
    }
    let close = format!("]{}]", "=".repeat(j - start - 1));
    src[j + 1..].find(&close).map(|p| j + 1 + p + close.len())
}

/// 返回 `local` 名字列表之后的位置（不含 `=`）。
fn local_name_list_end(toks: &[Tok], i: usize) -> usize {
    let n = toks.len();
    let mut k = i + 1;
    if k < n && toks[k].text == "function" {
        return k + 2;
    }
    while k < n {
        if toks[k].kind != KIND_WORD || is_keyword(&toks[k].text) {
            break;
        }
        k += 1;
        if k < n && toks[k].text == "," {
            k += 1;
            continue;
        }
        break;
    }
    k
}

/// 这个名字是否在「非调用位置」被用过（作为值传递等）。槽位化后这类用法依然
/// 可用（`u[0x..]` 就是那个值），所以只用来决定是否值得改，不是安全条件。
fn bare_ref_global(name: &str, body: &[Tok]) -> bool {
    for (i, t) in body.iter().enumerate() {
        if t.kind == KIND_WORD && t.text == name {
            let prev_dot = i > 0 && (body[i - 1].text == "." || body[i - 1].text == ":");
            let next_call = i + 1 < body.len() && body[i + 1].text == "(";
            if prev_dot || !next_call {
                return true;
            }
        }
    }
    false
}

/// shell 形参名也不能槽位化（否则形参被遮蔽后又「重新可见」，语义变化）。
fn names_in_params(n: &str, params: &[String]) -> bool {
    params.iter().any(|p| p == n)
}

/// 把 `local a, b, c = ...`（或 `local a, b`）整段换成 `u[0x..],u[0x..]=...`。
/// 只有「所有名字都已在槽位表里」时才替换，返回（替换文本，吃掉的 token 数）。
fn local_slot_prefix(
    toks: &[Tok],
    i: usize,
    slot_names: &HashMap<String, String>,
) -> Option<(String, usize)> {
    let n = toks.len();
    // `local function NAME(...)` → `u[0x..]=function(...)`
    if i + 2 < n && toks[i + 1].text == "function" && toks[i + 2].kind == KIND_WORD {
        if let Some(key) = slot_names.get(&toks[i + 2].text) {
            return Some((format!("u[{}]=function", key), 3));
        }
        return None;
    }
    let mut k = i + 1;
    let mut keys: Vec<String> = Vec::new();
    while k < n {
        if toks[k].kind != KIND_WORD || is_keyword(&toks[k].text) {
            break;
        }
        let key = slot_names.get(&toks[k].text)?;
        keys.push(format!("u[{}]", key));
        k += 1;
        if k < n && toks[k].text == "," {
            k += 1;
            continue;
        }
        break;
    }
    if keys.is_empty() {
        return None;
    }
    let lhs = keys.join(",");
    if k < n && toks[k].text == "=" {
        Some((format!("{}=", lhs), k - i + 1))
    } else {
        // 没有初始化：等价于赋 nil
        Some((format!("{}=nil;", lhs), k - i))
    }
}

fn fresh_field(rng: &mut GenRng, used: &mut HashSet<String>) -> String {
    const POOL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
    loop {
        let len = if rng.range(0, 100) < 78 { 2 } else { 1 };
        let mut s = String::new();
        for idx in 0..len {
            let c = if idx == 0 || s.is_empty() {
                POOL[rng.range(0, 53)]
            } else {
                POOL[rng.range(0, POOL.len())]
            };
            s.push(c as char);
        }
        if !is_keyword(&s) && used.insert(s.clone()) {
            return s;
        }
    }
}

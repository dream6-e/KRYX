// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
// 解码器控制流混淆：把每条功能语句包进随机化的控制流。
//
// 原则（用户 2026-11-17 / 2026-11-18 指示）：
// - 多用 repeat/while/for 代替裸 if；elseif 与 else if 混用
// - 判断条件里 60% 左右引用 scratch 变量 `_`（解码器入口统一 hoist 一个 upvalue `_`）
// - 常量对比（如 a>b、c<d、_>5031）全部随机生成：变量/常量/算术式随机组合，
//   not/and/or 随机嵌套；没有固定形态（如 a==2 and nil 之类不再硬编码）
// - 多层嵌套判断，不要单层 if 裸奔
// - 不走的分支用 break / return 随机数字或变量
// - 重复 until 的收尾条件也全随机生成，不再固定为 `until not nil`
// - 判断用 not / and / or 组合，scratch 变量复用，尽量少声明 local
//
// 保留给 entry 的 4 个常量局部变量 a/b/c/d（随机选取且严格 a>b>c>d），
// 它们经 compressor 直通重命名（keep-list），输出里会直接看到 `a>b` 这类判断
//
// 正确性铁律：
// - 每个 wrapper 执行 BODY 恰好一次，且所有条件的真假都在生成期被精确推算
// - 真实循环（m_bxor / m_next / 初始化循环）的守卫只用 const_true，不能引用 `_`
// - DEAD 分支永远不执行（条件恒真/恒假由常量保证），其中的 return/break 仅需语法合法
use crate::VM::VM_Backend::Generator::GenRng;
use std::cell::{Cell, RefCell};

thread_local! {
    /// entry 里随机抽取的 4 个常量值（a>b>c>d），用于判断条件的真假推算
    static CONST_VALS: Cell<[i64; 4]> = Cell::new([1500, 1000, 600, 200]);
    /// 复用的数字池：整份产物只用这一小批数字，其余数字全部由计算得出
    static NUM_POOL: RefCell<Vec<i64>> = RefCell::new(Vec::new());
}

/// 由 packer 在装配时写入 entry 常量（与 `local a,b,c,d = ...` 保持一致）
pub fn set_constants(a: i64, b: i64, c: i64, d: i64) {
    CONST_VALS.with(|cell| cell.set([a, b, c, d]));
    NUM_POOL.with(|p| p.borrow_mut().clear());
}

/// 重建复用数字池（整份产物共用这一小批数字；由 packer 在开始生成时调用一次）
pub fn reset_numbers(rng: &mut GenRng) {
    let mut v: Vec<i64> = Vec::new();
    while v.len() < 9 {
        let k = rng.range(2, 97) as i64;
        if !v.contains(&k) {
            v.push(k);
        }
    }
    // 1 / 3 常在取模、步长里出现，固定留在池里
    v.push(1);
    v.push(3);
    NUM_POOL.with(|p| *p.borrow_mut() = v);
}

fn const_vals() -> [i64; 4] {
    CONST_VALS.with(|cell| cell.get())
}

/// Lua 的 `%` 是取模（结果符号跟除数走），Rust 的 `%` 是取余 —— 两者必须区分，
/// 否则 `_%7` 在 `_` 为负时真假会算错。
fn lua_mod(a: i64, m: i64) -> i64 {
    if m == 0 {
        return 0;
    }
    a.rem_euclid(m.abs())
}

/// 从**复用池**里取一个小数字（池子在每次生成开始时随机填一次，之后反复使用）。
/// 用户 2026-11-18 要求：控制流不要到处写普通数字，同一批数字反复用。
fn small(rng: &mut GenRng) -> i64 {
    let empty = NUM_POOL.with(|p| p.borrow().is_empty());
    if empty {
        let mut v: Vec<i64> = Vec::new();
        for _ in 0..7 {
            v.push(rng.range(2, 97) as i64);
        }
        v.push(1);
        v.push(3);
        NUM_POOL.with(|p| *p.borrow_mut() = v);
    }
    let n = NUM_POOL.with(|p| p.borrow().len());
    let i = rng.range(0, n);
    NUM_POOL.with(|p| p.borrow()[i])
}

thread_local! {
    /// 大数池（opaque predicate / 掩码用），同样反复复用
    static BIG_POOL: RefCell<Vec<i64>> = RefCell::new(Vec::new());
}

/// 重建大数池
pub fn set_big_pool(rng: &mut GenRng) {
    let mut v: Vec<i64> = Vec::new();
    for _ in 0..4 {
        v.push(rng.range64(0x10000, 0x3FFFFFFF));
    }
    BIG_POOL.with(|p| *p.borrow_mut() = v);
}

/// 取一个复用的大数
pub fn big_num(rng: &mut GenRng) -> i64 {
    let empty = BIG_POOL.with(|p| p.borrow().is_empty());
    if empty {
        set_big_pool(rng);
    }
    let n = BIG_POOL.with(|p| p.borrow().len());
    let i = rng.range(0, n);
    BIG_POOL.with(|p| p.borrow()[i])
}

/// 一个 2..=m 的小模数（取模运算用）
fn small_mod(rng: &mut GenRng, m: i64) -> i64 {
    2 + small(rng) % m.max(2)
}

/// 数字的书写形态：十进制 / 十六进制 / 二进制混用，带 `_` 分隔（与 sample2 一致）
fn fmt_num(rng: &mut GenRng, v: i64) -> String {
    if v < 0 {
        return format!("-{}", fmt_num(rng, -v));
    }
    match rng.range(0, 5) {
        0 => format!("0x{:X}", v),
        1 => format!("0b{:b}", v),
        2 => format!("0x{:x}", v),
        3 => format!("0X0_{:X}", v),
        _ => format!("{}", v),
    }
}

fn cmp_val(a: i64, b: i64, op: &str) -> bool {
    match op {
        ">" => a > b,
        ">=" => a >= b,
        "<" => a < b,
        "<=" => a <= b,
        "==" => a == b,
        "~=" => a != b,
        _ => unreachable!(),
    }
}

fn pick_op(rng: &mut GenRng) -> &'static str {
    const OPS: [&str; 6] = [">", ">=", "<", "<=", "==", "~="];
    OPS[rng.range(0, OPS.len())]
}

const LETTERS: [&str; 4] = ["a", "b", "c", "d"];

/// `not` 嵌套层数上限（用户 2026-11-21 要求：不大于 2 层）
const NOT_DEPTH_LIMIT: u32 = 2;

fn letter_val(vals: &[i64; 4], l: &str) -> i64 {
    match l {
        "a" => vals[0],
        "b" => vals[1],
        "c" => vals[2],
        "d" => vals[3],
        _ => 0,
    }
}

fn pick_letter(rng: &mut GenRng) -> &'static str {
    LETTERS[rng.range(0, 4)]
}

/// sample2 的招牌写法：`e+g-g+g+g`、`_+_-_-_-g`、`L+L-g-g`。
/// 由「字母常量 + 复用小数字」交替加减组成，展开值在生成期精确推算。
fn noise_chain(rng: &mut GenRng, v: i64) -> (String, i64) {
    let vals = const_vals();
    let n = 3 + rng.range(0, 4); // 3~6 项
    let mut s = String::new();
    let mut val = v;
    for i in 0..n {
        let plus = rng.range(0, 2) == 0;
        // 交替使用字母常量与池中数字，sample2 里两者都高频出现
        let token = if rng.range(0, 3) == 0 {
            let l = LETTERS[rng.range(0, 4)];
            val = if plus { val + letter_val(&vals, l) } else { val - letter_val(&vals, l) };
            l.to_string()
        } else {
            let k = small(rng);
            val = if plus { val + k } else { val - k };
            fmt_num(rng, k)
        };
        if i == 0 && plus {
            // 第一项若为正号，直接接在后面（`L+e`），不加 `+`
            s.push_str(&token);
        } else {
            s.push(if plus { '+' } else { '-' });
            s.push_str(&token);
        }
    }
    (s, val)
}

fn compound_chain(rng: &mut GenRng) -> (Vec<String>, i64) {
    let vals = const_vals();
    let mut v = vals[3];
    let mut out: Vec<String> = vec![format!("_={}", LETTERS[3])];
    let steps = 1 + rng.range(0, 3);
    for _ in 0..steps {
        match rng.range(0, 6) {
            0 => {
                let k = small_mod(rng, 9);
                out.push(format!("_*={}", fmt_num(rng, k)));
                v = v.saturating_mul(k);
            }
            1 => {
                let l = LETTERS[2];
                out.push(format!("_+={}", l));
                v = v.saturating_add(letter_val(&vals, l));
            }
            2 => {
                let k = small(rng);
                let l = LETTERS[1];
                out.push(format!("_={}", fmt_num(rng, k)));
                v = k;
                out.push(format!("_+={}", l));
                v = v.saturating_add(letter_val(&vals, l));
            }
            3 => {
                let k = small(rng);
                out.push(format!("_-={}", fmt_num(rng, k)));
                v = v.saturating_sub(k);
            }
            4 => {
                let m = small_mod(rng, 40);
                let base = m + small(rng);
                out.push(format!("_={}", fmt_num(rng, base)));
                v = base;
                out.push(format!("_%={}", fmt_num(rng, m)));
                v = lua_mod(base, m);
            }
            _ => {
                let m = small_mod(rng, 9) + 1;
                let base = m * small_mod(rng, 5);
                out.push(format!("_={}", fmt_num(rng, base)));
                v = base;
                out.push(format!("_//={}", fmt_num(rng, m)));
                v = base / m;
            }
        }
    }
    (out, v)
}

/// `_` 初值：全部由 a/b/c/d 与复用数字**计算**得出，随后按 sample2 的写法
/// 继续做「噪声加减链」或「复合运算符链」。
/// 返回 (语句文本, `_` 的最终已知值)。
fn seed(rng: &mut GenRng) -> (String, i64) {
    let vals = const_vals();
    // 每条语句单独进向量，最后用 `;` 连接 —— 不能直接拼，否则会出现非法的 `;;`
    let mut stmts: Vec<String> = Vec::new();

    // 以字母常量起始的初值（sample2 里状态量几乎都由常量推出）
    let (mut v, first) = match rng.range(0, 6) {
        0 => (vals[3], format!("_={}", LETTERS[3])),
        1 => (vals[2], format!("_={}", LETTERS[2])),
        2 => (vals[1], format!("_={}", LETTERS[1])),
        3 => {
            let m = small_mod(rng, 61);
            (lua_mod(vals[2], m), format!("_={}%{}", LETTERS[2], fmt_num(rng, m)))
        }
        4 => {
            let m = small_mod(rng, 61);
            (lua_mod(vals[0], m), format!("_={}%{}", LETTERS[0], fmt_num(rng, m)))
        }
        _ => {
            let k = small(rng);
            (k, format!("_={}", fmt_num(rng, k)))
        }
    };
    stmts.push(first);

    // sample2 的两种招牌写法混用：
    //   A) `_=_+(e+g-g+g+g)` —— 字母/数字噪声链
    //   B) `_+=e; _*=k; _%=m` —— 复合运算符链
    if rng.range(0, 2) == 0 {
        let (chain, dv) = noise_chain(rng, 0);
        v = v.saturating_add(dv);
        stmts.push(format!("_=_+({})", chain));
    } else {
        let (pieces, cv) = compound_chain(rng);
        for p in pieces {
            stmts.push(p);
        }
        v = cv;
    }

    // 再加 0~2 步噪声加减，长度与 sample2 的 `_+_-_-_-g` 相当
    for _ in 0..rng.range(0, 3) {
        let (chain, dv) = noise_chain(rng, 0);
        let minus = rng.range(0, 3) == 0;
        stmts.push(format!("_{}({})", if minus { "-=" } else { "+=" }, chain));
        v = if minus { v.saturating_sub(dv) } else { v.saturating_add(dv) };
    }

    // 让数值落进小范围，后续比较区间才可控
    let m = small_mod(rng, 50) + 9;
    v = lua_mod(v, m);
    stmts.push(format!("_%={}", fmt_num(rng, m)));

    // 铁律：`if not _ then <死> else <正文> end`、`if not(not _) then <正文> end`
    // 这几个 wrapper 都要求 `_ ~= 0`，取模后可能刚好是 0，必须推离 0。
    if v == 0 {
        let k = small(rng);
        v = k;
        stmts.push(format!("_+={}", fmt_num(rng, k)));
    }
    // 全部语句都结束在 `_` 上，后面接判断不可能出现空语句或悬空分号
    let t = stmts.join(";");
    if std::env::var("KRYX_DEBUG_SEED").is_ok() {
        eprintln!("SEED\t{},{},{},{}\t{}\t{}", vals[0], vals[1], vals[2], vals[3], v, t);
    }
    (t, v)
}

/// 恒等算术噪音：`a+0>b` 这种写法里的 0 也换成复用数字（`(a+3-3)>b`）。
fn fmt_letter_cmp(rng: &mut GenRng, l1: &str, op: &str, l2: &str) -> String {
    match rng.range(0, 4) {
        0 | 3 => format!("{}{}{}", l1, op, l2),
        1 => {
            let k = small(rng);
            format!("({}+{}-{}){}{}", l1, fmt_num(rng, k), fmt_num(rng, k), op, l2)
        }
        _ => {
            let k = small(rng);
            format!("{}{}({}-{}+{})", l1, op, l2, fmt_num(rng, k), fmt_num(rng, k))
        }
    }
}

/// `_` 相关的原子判断：两侧都是**算出来的**，`_` 的实际值按 v 精确推算
fn atom_underscore(rng: &mut GenRng, v: i64) -> (String, bool) {
    let k = small(rng);
    let k2 = small(rng);
    match rng.range(0, 8) {
        // (_+k) op k2
        0 => {
            let op = pick_op(rng);
            (
                format!("(_+{}){}{}", fmt_num(rng, k), op, fmt_num(rng, k2)),
                cmp_val(v + k, k2, op),
            )
        }
        // (_*k+k2) op k3
        1 => {
            let k3 = small(rng);
            let op = pick_op(rng);
            (
                format!("(_*{}+{}){}{}", fmt_num(rng, k), fmt_num(rng, k2), op, fmt_num(rng, k3)),
                cmp_val(v * k + k2, k3, op),
            )
        }
        // _%m op r（取模判余）
        2 => {
            let m = small_mod(rng, 61);
            let r = lua_mod(k, m);
            let op = if rng.range(0, 2) == 0 { "==" } else { "~=" };
            (
                format!("_%{}{}{}", fmt_num(rng, m), op, fmt_num(rng, r)),
                cmp_val(lua_mod(v, m), r, op),
            )
        }
        // (_+k)%m op r
        3 => {
            let m = small_mod(rng, 61);
            let r = lua_mod(k2, m);
            let op = if rng.range(0, 2) == 0 { "==" } else { "~=" };
            (
                format!("(_+{})%{}{}{}", fmt_num(rng, k), fmt_num(rng, m), op, fmt_num(rng, r)),
                cmp_val(lua_mod(v + k, m), r, op),
            )
        }
        // _ op a%k（与常量变量算出来的值比）
        4 => {
            let vals = const_vals();
            let m = small_mod(rng, 61);
            let op = pick_op(rng);
            (
                format!("_{}{}%{}", op, LETTERS[0], fmt_num(rng, m)),
                cmp_val(v, lua_mod(vals[0], m), op),
            )
        }
        // (_*k) op d%m
        5 => {
            let vals = const_vals();
            let m = small_mod(rng, 61);
            let op = pick_op(rng);
            (
                format!("(_*{}){}{}%{}", fmt_num(rng, k), op, LETTERS[3], fmt_num(rng, m)),
                cmp_val(v * k, lua_mod(vals[3], m), op),
            )
        }
        // _ op (_%m+k)：等式两侧都引用同一个 `_`
        6 => {
            let m = small_mod(rng, 61);
            let op = pick_op(rng);
            (
                format!("_{}(_%{}+{})", op, fmt_num(rng, m), fmt_num(rng, k2)),
                cmp_val(v, lua_mod(v, m) + k2, op),
            )
        }
        // (_-k) op b%m
        _ => {
            let vals = const_vals();
            let m = small_mod(rng, 61);
            let op = pick_op(rng);
            (
                format!("(_-{}){}{}%{}", fmt_num(rng, k), op, LETTERS[1], fmt_num(rng, m)),
                cmp_val(v - k, lua_mod(vals[1], m), op),
            )
        }
    }
}

/// 字母常量之间的比较（如 a>b、c<=d），真假按 entry 里的实际常量值推算
fn atom_letter(rng: &mut GenRng) -> (String, bool) {
    let vals = const_vals();
    let l1 = pick_letter(rng);
    let mut l2 = pick_letter(rng);
    while l2 == l1 {
        l2 = pick_letter(rng);
    }
    let op = pick_op(rng);
    (
        fmt_letter_cmp(rng, l1, op, l2),
        cmp_val(letter_val(&vals, l1), letter_val(&vals, l2), op),
    )
}

/// 字母常量与**计算出来的数字**比较（如 a>d%17+3），真假精确推算
fn atom_letter_const(rng: &mut GenRng) -> (String, bool) {
    let vals = const_vals();
    let l = pick_letter(rng);
    let op = pick_op(rng);
    let other = if rng.range(0, 3) == 0 { LETTERS[3] } else { LETTERS[2] };
    let m = small_mod(rng, 61);
    let k = small(rng);
    let rhs = lua_mod(letter_val(&vals, other), m) + k;
    let rhs_txt = format!("{}%{}+{}", other, fmt_num(rng, m), fmt_num(rng, k));
    if rng.range(0, 4) == 0 {
        (
            format!("{}{}{}", rhs_txt, op, l),
            cmp_val(rhs, letter_val(&vals, l), op),
        )
    } else {
        (
            format!("{}{}{}", l, op, rhs_txt),
            cmp_val(letter_val(&vals, l), rhs, op),
        )
    }
}

/// 「常数」比较也改成两边都是计算式（如 a%17 > d%13+2），不再出现两个裸字面量
fn atom_const(rng: &mut GenRng) -> (String, bool) {
    let vals = const_vals();
    let op = pick_op(rng);
    let m1 = small_mod(rng, 61);
    let m2 = small_mod(rng, 61);
    let k = small(rng);
    // 文本固定是 `a%m1 op d%m2+k`，真值必须用同样的 a / d，不能另抽字母
    let lhs = lua_mod(vals[0], m1);
    let rhs = lua_mod(vals[3], m2) + k;
    (
        format!(
            "{}%{}{}{}%{}+{}",
            LETTERS[0],
            fmt_num(rng, m1),
            op,
            LETTERS[3],
            fmt_num(rng, m2),
            fmt_num(rng, k)
        ),
        cmp_val(lhs, rhs, op),
    )
}

/// 可选的加法噪音二字母比较（如 a+k>b）
fn atom(rng: &mut GenRng, v: Option<i64>) -> (String, bool) {
    match rng.range(0, 10) {
        // 60% 的原子用 `_`（如果允许）
        0..=5 => match v {
            Some(vv) => atom_underscore(rng, vv),
            None => {
                if rng.range(0, 2) == 0 { atom_letter(rng) } else { atom_const(rng) }
            }
        },
        6..=7 => atom_letter(rng),
        8 => atom_letter_const(rng),
        _ => atom_const(rng),
    }
}

/// 统一的随机布尔表达式生成器：
/// - 1~3 个原子，随机 and/or 连接
/// - 每个原子可带 0~2 个 not() 包装
/// - `force=true` 保证整体恒真，`force=false` 保证整体恒假
fn gen_bool(rng: &mut GenRng, v: Option<i64>, force: bool) -> String {
    {
        let want_underscore = v.is_some() && matches!(rng.range(0, 10), 0..=5);
        let n_leaves = 1 + if rng.range(0, 10) < 4 { 1 } else { 0 } + if rng.range(0, 10) < 2 { 1 } else { 0 };

        // `not` 嵌套上限（用户要求：整条条件的 not 嵌套不超过 2 层）。
        // 每个原子的 not 层数独立随机，但最终整体取反时如果会让深度超过
        // 上限，就改用等价的 `<expr>==false` 写法，绝不产生第三层 not。
        let mut leaves: Vec<(String, bool, u32)> = Vec::with_capacity(n_leaves);
        let mut max_not = 0u32;
        for _ in 0..n_leaves {
            let leaf_v = if want_underscore { v } else {
                // 这个原子不强制用 `_`，按原子级 60/40 规则
                if v.is_some() && rng.range(0, 10) < 6 { v } else { None }
            };
            let (txt, tr) = atom(rng, leaf_v);
            let nots = rng.range(0, NOT_DEPTH_LIMIT as usize + 1) as u32; // 0..=2
            max_not = max_not.max(nots);
            let mut t = tr;
            let mut s = txt;
            for _ in 0..nots {
                s = format!("not({})", s);
                t = !t;
            }
            leaves.push((s, t, nots));
        }

        let mut expr = leaves[0].0.clone();
        let mut truth = leaves[0].1;
        for leaf in leaves.iter().skip(1) {
            // 必须带括号：Lua 里 and 优先级高于 or，若写 `A or B and C`，
            // 其语义是 A or (B and C)，与这里的左结合真值推算不一致
            if rng.range(0, 2) == 0 {
                expr = format!("({} and {})", expr, leaf.0);
                truth = truth && leaf.1;
            } else {
                expr = format!("({} or {})", expr, leaf.0);
                truth = truth || leaf.1;
            }
        }

        if n_leaves > 1 && rng.range(0, 2) == 0 {
            expr = format!("({})", expr);
        }
        if truth != force {
            // 整体取反。再加一层 not 会让深度变成 max_not+1：
            // 只要不超过上限就用 not(...)，否则用等价的 (expr)==false。
            if max_not < NOT_DEPTH_LIMIT {
                expr = format!("not({})", expr);
            } else {
                expr = format!("({})==false", expr);
            }
        }
        expr
    }

}

/// 恒真判断（按 v 精确推算；Some 时 60% 原子用 `_`）
fn truthy(rng: &mut GenRng, v: Option<i64>) -> String {
    gen_bool(rng, v, true)
}

/// 恒假判断（按 v 精确推算）
fn falsy(rng: &mut GenRng, v: Option<i64>) -> String {
    gen_bool(rng, v, false)
}

/// 恒真常量表达式（不涉及 `_`），用于真实循环守卫
pub fn const_true(rng: &mut GenRng) -> String {
    gen_bool(rng, None, true)
}

/// 恒假常量表达式（不涉及 `_`）
#[allow(dead_code)]
pub fn const_false(rng: &mut GenRng) -> String {
    gen_bool(rng, None, false)
}

/// 恒真判断（Some(v) 时可 60% 用 `_`）
pub fn guard_true(rng: &mut GenRng) -> String {
    truthy(rng, None) // 兼容旧调用点：不绑定 v，纯常量
}

/// 恒假判断
pub fn guard_false(rng: &mut GenRng) -> String {
    falsy(rng, None)
}

/// until 收尾（恒真，保证单趟）——全随机，不再固定为 `until not nil`。
/// 铁律：until 条件在 BODY 之后求值，而 BODY 可能改写 scratch `_`，
/// 因此 until 只允许使用不含 `_` 的纯常量判断（否则真假不可推算，单趟性被打破）。
fn gen_until(rng: &mut GenRng) -> String {
    gen_bool(rng, None, true)
}

/// 死分支：永不执行。返回值同样来自**计算**，不写裸大数字。
fn dead(rng: &mut GenRng) -> String {
    match rng.range(0, 4) {
        0 => {
            let k = small(rng);
            format!("return {}+{}", LETTERS[1], fmt_num(rng, k))
        }
        1 => {
            let k = small(rng);
            format!("do local _=_*{};return _ end", fmt_num(rng, k))
        }
        // 注意：不能写 `return _` / `_=_;return _`。死分支总在 BODY **之后**求值
        // （`if <恒真> then BODY else DEAD end`），此时 `_` 已被 BODY 重写，
        // 可能是 nil，一旦走到这里就返回 nil，把功能语句的结果吞掉。
        2 => {
            let k = small(rng);
            format!("return {}-{}", LETTERS[1], fmt_num(rng, k))
        }
        _ => {
            let k = small(rng);
            let m = small_mod(rng, 40);
            format!("return {}%{}+{}", LETTERS[0], fmt_num(rng, m), fmt_num(rng, k))
        }
    }
}

/// elseif 与 else if 两种拼写混用：随机构造链
fn elseif_chain(rng: &mut GenRng, body: &str) -> String {
    let (sd, v) = seed(rng);
    let use_elseif = rng.range(0, 2) == 0;
    if use_elseif {
        format!(
            "{};if {} then {} elseif {} then {} else {} end",
            sd,
            falsy(rng, Some(v)),
            dead(rng),
            truthy(rng, Some(v)),
            body,
            dead(rng)
        )
    } else {
        format!(
            "{};if {} then {} else if {} then {} else {} end end",
            sd,
            falsy(rng, Some(v)),
            dead(rng),
            truthy(rng, Some(v)),
            body,
            dead(rng)
        )
    }
}

/// 把一条功能语句包进随机控制流（每次混淆结果都不同）。
/// `body` 必须是单条 Lua 语句（可含内部任意控制流），不含尾 `end` 匹配问题。
pub fn wrap_stmt(body: &str, rng: &mut GenRng) -> String {
    // 状态机在 BODY 之后还要补 `break;`，所以 BODY 自身不能已经带走控制流
    //（`return` / `break` / `continue` 都必须是块的最后一条语句，后面不能再接东西）。
    let body_has_jump = body
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "return" || w == "break" || w == "continue");
    if !body_has_jump && rng.range(0, 100) < 40 {
        return state_machine(body, rng);
    }
    // 每个 wrapper 都先跑一段 `_` 的计算链，后续判断全部引用这个 `_`
    let (sd, v) = seed(rng);
    // 外层统一补分号：wrapper 以 end 收尾时，后续 `st=...` 等 token 不会被粘成一个标识符
    let out = match rng.range(0, 20) {
        // if + 随机恒真条件（scratch 复用 + 恒真判断）
        0 => format!("{};if {} then {} else {} end", sd, truthy(rng, Some(v)), body, dead(rng)),
        // 纯常量守卫 if（不碰 _）
        1 => format!("if {} then {} else {} end", const_true(rng), body, dead(rng)),
        // if not _ then ... else ...（scratch 恒真取反恒假）
        2 => format!("{};if not _ then {} else {} end", sd, dead(rng), body),
        // 双 not：if not(not _)
        3 => format!("{};if not(not _) then {} else {} end", sd, body, dead(rng)),
        // repeat ... until <随机恒真条件>（单趟环，不再固定 not nil）
        4 => format!(
            "{};repeat if {} then {} else {} end until {}",
            sd,
            truthy(rng, Some(v)),
            body,
            dead(rng),
            gen_until(rng)
        ),
        // repeat + 单侧死分支
        5 => format!(
            "{};repeat if {} then {} end {} until {}",
            sd,
            falsy(rng, Some(v)),
            dead(rng),
            body,
            gen_until(rng)
        ),
        // for __=1,1（loop 变量名不能遮蔽刮擦 `_` —— BODY 里的 `_` 必须绑定到 entry hoist 的 upvalue）
        6 => format!("for __=1,1 do if __==1 then {} else {} end end", body, dead(rng)),
        // elseif 与 else if 两种拼写混用（随机构造链）
        7 => elseif_chain(rng, body),
        // 双层 if 嵌套（多层条件）：死分支的返回值也是算出来的
        8 => {
            let k = small(rng);
            let k2 = small(rng);
            format!(
                "{};if {} then if {} then {} else return {}+{} end else return {}-{} end",
                sd,
                truthy(rng, Some(v)),
                truthy(rng, Some(v)),
                body,
                LETTERS[2],
                fmt_num(rng, k),
                LETTERS[3],
                fmt_num(rng, k2)
            )
        }
        // 用户例子：if not _ then else if _ and <恒真> or not _ then --代码 end end
        9 => format!("{};if not _ then else if _ and {} or not _ then {} end end", sd, truthy(rng, Some(v)), body),
        // 用户例子：if not _ then elseif not _ and <恒假> then else --代码 end
        10 => format!("{};if not _ then elseif not _ and {} then else {} end", sd, falsy(rng, Some(v)), body),
        // 用户例子：repeat _==v and nil 风格
        11 => format!(
            "{};repeat if _==_ and {} then else if {} then {} else break end end until {}",
            sd,
            falsy(rng, Some(v)),
            truthy(rng, Some(v)),
            body,
            gen_until(rng)
        ),
        // repeat + 双层 if（多层条件嵌套）
        12 => {
            let k = small(rng);
            let k2 = small(rng);
            format!(
                "{};repeat if {} then if {} then {} else do return {}+{} end end else do return {}*{} end end until {}",
                sd,
                truthy(rng, Some(v)),
                const_true(rng),
                body,
                LETTERS[1],
                fmt_num(rng, k),
                LETTERS[3],
                fmt_num(rng, k2),
                gen_until(rng)
            )
        }
        // for + elseif（混拼写）
        13 => {
            if rng.range(0, 2) == 0 {
                format!("for __=1,1 do if __==1 then {} else break end end", body)
            } else {
                format!("for __=1,1 do if not __ then break else if __==1 then {} else break end end end", body)
            }
        }
        // 常量守卫嵌套 repeat（多层 + 非 scratch 判断）
        14 => {
            let k = small(rng);
            format!(
                "if {} then repeat if {} then {} else {} end until {} else return {}%{} end",
                const_true(rng),
                const_true(rng),
                body,
                dead(rng),
                gen_until(rng),
                LETTERS[0],
                fmt_num(rng, k)
            )
        }
        // 单趟 repeat：body 直接躺在环里，until 全随机
        15 => format!("{};repeat {} until {}", sd, body, gen_until(rng)),
        // 三层嵌套 if（字母常量比较在里面随机出现）
        16 => {
            let k = small(rng);
            let k2 = small(rng);
            format!(
                "{};if {} then if {} then if {} then {} else do return {}%{} end end else do return {}-{} end end else do return b+{} end end",
                sd,
                truthy(rng, Some(v)),
                truthy(rng, None),
                truthy(rng, Some(v)),
                body,
                LETTERS[2],
                fmt_num(rng, k),
                LETTERS[1],
                fmt_num(rng, k2),
                {
                    let k3 = small(rng);
                    fmt_num(rng, k3)
                }
            )
        }
        // if <恒假> then dead else BODY end（反写单侧）
        17 => format!("if {} then {} else {} end", falsy(rng, None), dead(rng), body),
        // for + repeat 嵌套（两层循环 + 随机 until）
        18 => format!("for __=1,1 do repeat {} until {} end", body, gen_until(rng)),
        // 双包裹：if <字母常量恒真> then repeat BODY until <随机> end
        19 => format!("if {} then repeat {} until {} end", const_true(rng), body, gen_until(rng)),
        // 双层 repeat（嵌套单趟环）
        _ => format!("{};repeat repeat {} until {} until {}", sd, body, gen_until(rng), gen_until(rng)),
    };
    format!("{};", out)
}

/// 批量包装多条语句并拼接（用于 handler 函数体等）
pub fn wrap_all(stmts: &[String], rng: &mut GenRng) -> String {
    stmts
        .iter()
        .map(|s| wrap_stmt(s, rng))
        .collect::<Vec<_>>()
        .join("")
}

/// 包装一个多语句块（如 `local function ... end`、`local x = {...}` 等定义）。
/// 每条顶层语句都独立包进随机控制流，适合把 sample2 风格的 `local function`
/// 字符串解码器、`local o={...}` 查表定义等整体混淆。
///
/// 示例（混淆前）：
///   local function Z(j)
///     local j=m(j)
///     if not j then return Y end
///     return o and n[j]
///   end
///   local o={[256484652]={218,219,216,0xeb,221}}
///   local function m(Y)
///     local o=o[Y]
///     local Y=''
///     for p=0X_1_,#o do Y=Y..s((o[p]+256-0X_0_76)%256) end
///     return Y
///   end
///
/// 混淆后每条语句都被包进 `if/while/repeat/for` 等随机控制流，`_` 变量和
/// `a>b` 等字母常量对比会出现在条件里，`dead` 分支放不可达代码。
pub fn wrap_block(stmts: &[String], rng: &mut GenRng) -> String {
    stmts
        .iter()
        .map(|s| wrap_stmt(s, rng))
        .collect::<Vec<_>>()
        .join("")
}

// ─────────────────────────────────────────────────────────────────────────────
// sample2 真实控制流骨架：哨兵状态码状态机 + `repeat ... until false` + continue/break
//
// 样本里的典型形态（`D2` / `VP` / `i2` / `W2` / `_P` 等共 37 个 `while true`、
// 39 个 `repeat until false`、96 个 `continue`）：
//
//   D2=function(v,u)local m,f,K,p,h=99;while true do
//     if m==102 then ... m=0B01101;
//     elseif m==0B1101 then return -2,h;
//     elseif m==0B1100011 then p=u[53]();m=(0X66);... end
//   end ... end
//
//   repeat if h==0x50 then u=v:zP(u,f);break;
//          else if h==0B00111_0101 then ... h=0X50; end;end
//   until false;
//
//   repeat if u==122 then (v)[0B0101],v[48]=-(-0xFe),(-v[0X1e]);u=(17);continue;
//          else if u~=0X11 then else return-0b1;end;end
//   until false;
//
// 本函数按这个骨架生成：真实 dispatch 变量 + 真值状态迁移 + 实际执行的 BODY
// 只放在其中一个状态分支里；其余状态分支是「迁移」或不可达出口。
// 状态迁移值由生成期精确推算，保证 BODY 恰好执行一次、然后从循环里跳出。
// ─────────────────────────────────────────────────────────────────────────────

/// 状态字面量：`0x`/`0X`/`0b`/`0B`/十进制混用，含前导零与 `_`（与 sample2 一致）。
/// 约 30% 的场合改成**由复用数字算出来**的等价表达式（`0X50+3-3`、`-(-94)`），
/// 让控制流里的数字不是一堆孤立常量。
fn state_lit(rng: &mut GenRng, v: u32) -> String {
    match rng.range(0, 10) {
        0 | 1 => {
            let k = small(rng) as u32 % 40 + 1;
            if v > k {
                let a = state_lit_plain(rng, v - k);
                let b = state_lit_plain(rng, k);
                return format!("({}+{})", a, b);
            }
            let inner = state_lit_plain(rng, v);
            format!("-(-{})", inner)
        }
        2 => {
            let k = small(rng) as u32 % 20 + 1;
            let m = v + k;
            let a = state_lit_plain(rng, m);
            let b = state_lit_plain(rng, k);
            format!("({}-{})", a, b)
        }
        _ => state_lit_plain(rng, v),
    }
}

/// 状态机变量名池（与 sample2 的 `W` / `m` / `h` / `u` / `Z` / `L` 同名风格）
fn state_var(rng: &mut GenRng) -> String {
    const VARS: [&str; 6] = ["W", "m", "h", "u", "Z", "L"];
    VARS[rng.range(0, 6)].to_string()
}

/// 状态机的状态表：大小 n，值都在 2..200，互不相同
fn state_set(rng: &mut GenRng, n: usize) -> Vec<u32> {
    let mut states: Vec<u32> = Vec::with_capacity(n);
    while states.len() < n {
        let v = small(rng) as u32 % 199 + 2;
        if !states.contains(&v) {
            states.push(v);
        }
    }
    states
}

fn state_lit_plain(rng: &mut GenRng, v: u32) -> String {
    match rng.range(0, 4) {
        0 => {
            let mut s = format!("{:X}", v);
            if rng.range(0, 2) == 0 {
                s = format!("{}{}", "0".repeat(rng.range(1, 3)), s);
            }
            let s = us_noise(&s, rng);
            if rng.range(0, 2) == 0 { format!("0X{}", s) } else { format!("0x{}", s) }
        }
        1 => {
            let s = us_noise(&format!("{:b}", v), rng);
            if rng.range(0, 2) == 0 { format!("0B{}", s) } else { format!("0b{}", s) }
        }
        _ => format!("{}", v),
    }
}

/// 在数字字面量里随机插 1~2 个 `_`（Luau 解析前会剥离）
fn us_noise(s: &str, rng: &mut GenRng) -> String {
    let bytes: Vec<char> = s.chars().collect();
    let n = bytes.len();
    if n < 3 {
        return s.to_string();
    }
    let mut gaps: Vec<usize> = (1..n).collect();
    let k = if rng.range(0, 100) < 45 { 0 } else { 1 + rng.range(0, 2) };
    let mut out = String::with_capacity(n + k);
    for (i, c) in bytes.iter().enumerate() {
        out.push(*c);
        if i + 1 < n && k > 0 && gaps.contains(&(i + 1)) && rng.range(0, 4) == 0 {
            out.push('_');
            gaps.retain(|g| *g != i + 1);
        } else if i + 1 == n {
            break;
        }
        let _ = &mut gaps;
    }
    let mut g = gaps.clone();
    g.retain(|x| *x > 1);
    let extra = k.saturating_sub(out.chars().filter(|c| *c == '_').count());
    for _ in 0..extra {
        if let Some(pos) = g.pop() {
            let mut chars: Vec<char> = out.chars().collect();
            if pos <= chars.len() {
                chars.insert(pos, '_');
                out = chars.into_iter().collect();
            }
        }
    }
    out
}

/// 生成「状态变量等于 v」为真的判断表达式。四种拼写混用，与 sample2 一致：
/// `v==0X50`、`not(v~=0B1010000)`、`not(not(v==50))`、`v~=0X51 and v<0X52`
fn eq_test(rng: &mut GenRng, var: &str, v: u32) -> String {
    let lit = state_lit(rng, v);
    match rng.range(0, 12) {
        0..=5 => format!("{}=={}", var, lit),
        6..=7 => format!("not({}~={})", var, lit),
        8..=9 => format!("not(not({}=={}))", var, lit),
        _ => {
            let other = state_lit(rng, v ^ 1);
            format!("{}~={} and {}=={}", var, other, var, lit)
        }
    }
}

/// `while true do ... end` 版本的状态机（sample2 的 `D2` / `VP` / `i2` 形态）。
/// 出口只有 `break` / `return`，与外层语句继续衔接。
pub fn state_machine_while(body: &str, rng: &mut GenRng) -> String {
    let var = state_var(rng);
    let n = rng.range(3, 6);
    let states = state_set(rng, n);
    let body_idx = if rng.range(0, 100) < 70 { n - 1 } else { n - 2 };
    let use_elseif = rng.range(0, 2) == 0;

    let mut out = String::with_capacity(body.len() + 320);
    // sample2 里 37 处 `while true do` 就是字面 `true`；另有 `while-(-0B1011110)do`
    // 这类不透明恒真写法。两种混用。
    let guard = match rng.range(0, 10) {
        0..=5 => "true".to_string(),
        6..=7 => state_lit(rng, 1),
        // 恒真守卫：用 const_true（内部已受 NOT_DEPTH_LIMIT 约束），
        // 不要再手动套 not(...)，否则会和内部 not 叠加超限
        8 => const_true(rng),
        9 => format!("{}", truthy(rng, None)),
        _ => "-(-94)".to_string(),
    };
    out.push_str(&format!(
        "{}={};while {} do ",
        var,
        state_lit(rng, states[0]),
        guard
    ));
    for i in 0..n {
        if i == 0 {
            out.push_str(&format!("if {} then ", eq_test(rng, &var, states[i])));
        } else if use_elseif {
            out.push_str(&format!("elseif {} then ", eq_test(rng, &var, states[i])));
        } else {
            out.push_str(&format!("else if {} then ", eq_test(rng, &var, states[i])));
        }
        if i == body_idx {
            out.push_str(body);
            out.push_str(&format!("{}={};break;", var, state_lit(rng, states[0])));
        } else if i + 1 < n {
            out.push_str(&format!("{}={};", var, state_lit(rng, states[i + 1])));
            if rng.range(0, 4) != 0 {
                out.push_str("continue;");
            }
        } else {
            out.push_str("break;");
        }
    }
    let ends = if use_elseif { 1 } else { n };
    for _ in 0..ends {
        out.push_str(" end");
    }
    out.push_str(" end;");
    out
}

/// 生成一个 `repeat ... until false;` 状态机外壳，把 `body` 放进其中一个状态分支。
///
/// 结构（n 个状态）：
/// ```
/// m=0X0A; repeat
///   if m==0X0A then m=0X17;continue;
///   else if m==0X17 then <BODY> break;
///   else if m==0X21 then break; end;end;end
/// until false;
/// ```
/// 状态迁移值在生成期精确推算 ⇒ BODY 恰好执行一次、随后 break 出环。
pub fn state_machine(body: &str, rng: &mut GenRng) -> String {
    // 两种骨架混用（sample2 里 `repeat until false` 39 处、`while true` 37 处）：
    //   A) repeat ... until false;
    //   B) while true do ... end
    if rng.range(0, 100) < 45 {
        return state_machine_while(body, rng);
    }
    let var = state_var(rng);
    let n = rng.range(3, 6);
    let states = state_set(rng, n);
    // BODY 放在靠后的状态里（前面全是迁移态），偶尔提前一位
    let body_idx = if rng.range(0, 100) < 70 { n - 1 } else { n - 2 };
    // `elseif` 链（1 个 end）与 `else if` 嵌套（n 个 end）两种拼写混用，
    // 与 sample2 一致（样本 elseif 55 次、`else if` 也大量出现）。
    let use_elseif = rng.range(0, 2) == 0;

    let mut out = String::with_capacity(body.len() + 320);
    out.push_str(&format!("{}={};repeat ", var, state_lit(rng, states[0])));
    for i in 0..n {
        if i == 0 {
            out.push_str(&format!("if {} then ", eq_test(rng, &var, states[i])));
        } else if use_elseif {
            out.push_str(&format!("elseif {} then ", eq_test(rng, &var, states[i])));
        } else {
            out.push_str(&format!("else if {} then ", eq_test(rng, &var, states[i])));
        }
        if i == body_idx {
            out.push_str(body);
            if rng.range(0, 100) < 55 {
                out.push_str("break;");
            } else {
                // 出口：先把状态改成「下一态」再 break（sample2 常见）
                out.push_str(&format!("{}={};break;", var, state_lit(rng, states[(i + 1) % n])));
            }
        } else if i + 1 < n {
            out.push_str(&format!("{}={};", var, state_lit(rng, states[i + 1])));
            if rng.range(0, 4) != 0 {
                out.push_str("continue;");
            }
        } else {
            out.push_str("break;");
        }
    }
    // `elseif` 链只需 1 个 end；`else if` 嵌套需要 n 个 end
    let ends = if use_elseif { 1 } else { n };
    for _ in 0..ends {
        out.push_str(" end");
    }
    out.push_str(" until false;");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// 供 packer 直接拼装「第 10 类：缓存槽位」包装用的公开小工具。
//
// 这些只是把本文件里已有的 seed / 噪声链 / 数字池暴露出去，
// 让 packer 可以在自己拼的语句里复用同一套随机源，而不必重写一遍推算逻辑。
// ─────────────────────────────────────────────────────────────────────────────

/// 公开版 `seed`：返回 (初始化语句, `_` 的已知终值)。
pub fn seed_pub(rng: &mut GenRng) -> (String, i64) {
    seed(rng)
}

/// 公开版 `noise_chain`：返回 (噪声链文本, 链末的值)。
/// 链以 `+`/`-` 开头（调用方负责把它接在已有表达式后面）。
pub fn noise_pub(rng: &mut GenRng, v: i64) -> (String, i64) {
    noise_chain(rng, v)
}

/// 公开版 `small`：从复用数字池里取一个小数字。
pub fn small_pub(rng: &mut GenRng) -> i64 {
    small(rng)
}

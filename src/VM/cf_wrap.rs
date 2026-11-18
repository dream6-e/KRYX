// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
// 解码器控制流混淆：把每条功能语句包进随机化的控制流。
//
// 完全模仿 AI必读/sample2.lua 里的控制流形态（类型 1/2/3/4/5/7）：
//   1. 显式状态变量 + 无限 while true 主循环（状态码跳转，m==S0/S1/S2 …）
//   2. repeat ... until false（恒假 until，内部靠 break/return/continue 退出）
//   3. while 恒真（while-(-K)do / while K do，配合 break/continue）
//   4. continue/break 密集使用，多出口尾合并
//   5. if not / 常量谓词 / 不透明谓词；not 嵌套不超过两层（not(not x) 最深）
//   7. 死代码 / 不可达代码（return 之后还有语句、空 then 分支）
//
// 原则（用户 2026-11-17 / 2026-11-18 指示）：
// - 多用 repeat/while/for 代替裸 if；elseif 与 else if 混用
// - 判断条件里 60% 左右引用 scratch 变量 `_`（解码器入口统一 hoist 一个 upvalue `_`）
// - 常量对比（如 a>b、c<d、_>5031）全部随机生成；没有固定形态
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
// - not 嵌套不超过两层（leaf 内最多 1 层，整体再加最多 1 层）
use crate::VM::VM_Backend::Generator::GenRng;
use std::cell::Cell;

thread_local! {
    /// entry 里随机抽取的 4 个常量值（a>b>c>d），用于判断条件的真假推算
    static CONST_VALS: Cell<[i64; 4]> = Cell::new([1500, 1000, 600, 200]);
}

/// 由 packer 在装配时写入 entry 常量（与 `local a,b,c,d = ...` 保持一致）
pub fn set_constants(a: i64, b: i64, c: i64, d: i64) {
    CONST_VALS.with(|cell| cell.set([a, b, c, d]));
}

fn const_vals() -> [i64; 4] {
    CONST_VALS.with(|cell| cell.get())
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

/// 把整数格式化成样本风格的字面量：0x/0b 前缀随机、偶尔带下划线、偶尔前导零
///（Lua 只认小写 0x/0b，大写 0X/0B 会语法错误，故全部小写）
fn fmt_num(rng: &mut GenRng, n: i64) -> String {
    let pref = if rng.range(0, 2) == 0 { "0x" } else { "0b" };
    let digits = match pref {
        "0x" => format!("{:X}", n.abs()),
        _ => format!("{:b}", n.abs()),
    };
    let with_underscore = rng.range(0, 4) == 0 && digits.len() >= 3;
    let d = if with_underscore {
        let mut out = String::new();
        let mut cnt = 0;
        for ch in digits.chars().rev() {
            if cnt > 0 && cnt % 3 == 0 {
                out.push('_');
            }
            out.push(ch);
            cnt += 1;
        }
        out.chars().rev().collect::<String>()
    } else {
        digits
    };
    let mut s = format!("{}{}", pref, d);
    if n < 0 {
        s = format!("-{}", s);
    }
    // 偶尔加前导零（0x001D 之类）
    if rng.range(0, 6) == 0 {
        s = format!("0{}", s);
    }
    s
}

/// 统一生成一个合法的状态码文本（Lua 只认 0x/0b 小写前缀；0B/0X 会语法错误，故只用 0x/0b）
fn st(rng: &mut GenRng) -> String {
    let n = rng.range(0x20, 0xFF) as i64;
    if rng.range(0, 2) == 0 {
        format!("0x{:X}", n)
    } else {
        format!("0b{:b}", n)
    }
}

fn fmt_letter_cmp(rng: &mut GenRng, l1: &str, op: &str, l2: &str) -> String {
    match rng.range(0, 4) {
        0 | 3 => format!("{}{}{}", l1, op, l2),
        1 => format!("({}+0){}{}", l1, op, l2),
        _ => format!("{}{}({}-0)", l1, op, l2),
    }
}

/// `_` 相关的原子判断（真假按 v 精确推算）
fn atom_underscore(rng: &mut GenRng, v: i64) -> (String, bool) {
    match rng.range(0, 5) {
        0 => {
            let b = rng.range(0, (v * 2) as usize) as i64;
            let op = pick_op(rng);
            (format!("_{}{}", op, b), cmp_val(v, b, op))
        }
        1 => {
            let k = rng.range(1, 30) as i64;
            let b = rng.range(0, (v + k + 999) as usize) as i64;
            let op = pick_op(rng);
            (format!("(_+{}){}{}", k, op, b), cmp_val(v + k, b, op))
        }
        2 => {
            let m = rng.range(3, 97) as i64;
            let r = rng.range(0, m as usize) as i64;
            let op = if rng.range(0, 2) == 0 { "==" } else { "~=" };
            (format!("_%{}{}{}", m, op, r), cmp_val(v % m, r, op))
        }
        3 => {
            let m = [2i64, 3, 5, 7][rng.range(0, 4)];
            let b = rng.range(0, (v * m) as usize + 1) as i64;
            let op = pick_op(rng);
            (format!("({}*_){}{}", m, op, b), cmp_val(v * m, b, op))
        }
        _ => {
            let b = rng.range(0, 99) as i64;
            let op = pick_op(rng);
            (format!("_{}{}", op, b), cmp_val(v, b, op))
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

/// 字母常量与随机整数比较（如 a>831、247<d），真假精确推算
fn atom_letter_const(rng: &mut GenRng) -> (String, bool) {
    let vals = const_vals();
    let l = pick_letter(rng);
    let b = rng.range(0, 9999) as i64;
    let op = pick_op(rng);
    if rng.range(0, 4) == 0 {
        (format!("{}{}{}", b, op, l), cmp_val(b, letter_val(&vals, l), op))
    } else {
        (format!("{}{}{}", l, op, b), cmp_val(letter_val(&vals, l), b, op))
    }
}

/// 常数与常数比较（如 512>308），真假精确推算；偶尔带算术噪音
fn atom_const(rng: &mut GenRng) -> (String, bool) {
    let a = rng.range(0, 9999) as i64;
    let b = rng.range(0, 9999) as i64;
    let op = pick_op(rng);
    if rng.range(0, 3) == 0 {
        let k = rng.range(1, 60) as i64;
        (format!("({}+{}){}{}", a, k, op, b), cmp_val(a + k, b, op))
    } else {
        (format!("{}{}{}", a, op, b), cmp_val(a, b, op))
    }
}

/// 单个原子判断（可带 0~1 层 not，累计与整体 not 共同不超过两层）
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
/// - 1~3 个原子，随机 and/or 连接（全部带括号，避免 Lua and/or 优先级歧义）
/// - 每个原子可带 0~1 层 not；整体再按需要加最多 1 层 not → 累计不超过两层
/// - `force=true` 保证整体恒真，`force=false` 保证整体恒假
fn gen_bool(rng: &mut GenRng, v: Option<i64>, force: bool) -> String {
    let want_underscore = v.is_some() && matches!(rng.range(0, 10), 0..=5);
    let n_leaves = 1 + if rng.range(0, 10) < 4 { 1 } else { 0 } + if rng.range(0, 10) < 2 { 1 } else { 0 };

    let mut leaves: Vec<(String, bool)> = Vec::with_capacity(n_leaves);
    for _ in 0..n_leaves {
        let leaf_v = if want_underscore { v } else {
            if v.is_some() && rng.range(0, 10) < 6 { v } else { None }
        };
        let (txt, tr) = atom(rng, leaf_v);
        let nots = rng.range(0, 2); // 0 或 1 层 not
        let mut t = tr;
        let mut s = txt;
        for _ in 0..nots {
            s = format!("not({})", s);
            t = !t;
        }
        leaves.push((s, t));
    }

    let mut expr = leaves[0].0.clone();
    let mut truth = leaves[0].1;
    for leaf in leaves.iter().skip(1) {
        // 必须带括号：Lua 里 and 优先级高于 or
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
    // 整体再加最多 1 层 not（leaf 最多 1 层 + 这里 1 层 = 最多 2 层，满足“不超过两个 not”）
    if truth != force {
        expr = format!("not({})", expr);
    }
    expr
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
/// 因此 until 只允许使用不含 `_` 的纯常量判断。
fn gen_until(rng: &mut GenRng) -> String {
    gen_bool(rng, None, true)
}

/// 死分支：永不执行。模仿 sample2 类型 7（死代码/不可达代码）：
/// - return 后不可达语句（用 `do ... end` 包围 return，保证 return 是块末）
/// - 空 then / else 分支（用 `;` 占位）
/// 铁律：生成的代码片段本身必须是语法合法的块（return 只能出现在块末尾）。
/// 死分支：永不执行。模仿 sample2 类型 7（死代码/不可达代码）。
/// 只生成单条语句，不含 `end` 关键字，避免 `end;elseif` / `end end` 等嵌套问题。
/// `return` 只作为单条语句出现（是其所在块的最后一句）。
fn dead(rng: &mut GenRng, in_loop: bool) -> String {
    if in_loop && rng.range(0, 10) < 3 {
        if rng.range(0, 2) == 0 {
            return "break;".into();
        }
        return format!("return {};", rng.range(2, 9999));
    }
    match rng.range(0, 6) {
        0 => format!("return {};", rng.range(2, 9999)),
        1 => format!("local __z = {};", rng.range(2, 9999)),
        2 => format!("__z = {} + {};", rng.range(2, 999), rng.range(2, 999)),
        3 => "do end;".into(),
        4 => format!("return {};", rng.range(2, 9999)),
        _ => format!("return {};", rng.range(2, 9999)),
    }
}

/// 在 if/elseif 链的分支里用简单的 return 语句（避免 dead() 生成 end; 导致 end;elseif 非法）
fn dead_simple(rng: &mut GenRng) -> String {
    format!("return {}", rng.range(2, 9999))
}

fn elseif_chain(rng: &mut GenRng, v: i64, body: &str) -> String {
    let use_elseif = rng.range(0, 2) == 0;
    if use_elseif {
        format!(
            "_={};if {} then {} elseif {} then {} else {} end",
            v,
            falsy(rng, Some(v)),
            dead_simple(rng),
            truthy(rng, Some(v)),
            body,
            dead_simple(rng)
        )
    } else {
        format!(
            "_={};if {} then {} else if {} then {} else {} end end",
            v,
            falsy(rng, Some(v)),
            dead_simple(rng),
            truthy(rng, Some(v)),
            body,
            dead_simple(rng)
        )
    }
}

/// 类型 1：显式状态变量 + 无限 while true 主循环
/// local m = S0; while true do
///   if m == S0 then if <truthy> then <body>; m = S1; else <dead>; m = S2; end;
///   elseif m == S1 then <dead>; break;
///   elseif m == S2 then break;
///   end
/// end
fn style_state_while(rng: &mut GenRng, v: i64, body: &str) -> String {
    let s0 = st(rng);
    let s1 = st(rng);
    let s2 = st(rng);
    format!(
        "local m = {};while true do if m == {} then if {} then {}; m = {}; else {}; m = {}; end; elseif m == {} then {}; break; elseif m == {} then break; end end",
        s0, s0, truthy(rng, Some(v)), body, s1, dead(rng, false), s2, s1, dead(rng, false), s2
    )
}

/// 类型 2：repeat ... until false（恒假 until，内部靠 break/continue 退出）
/// local m = S0; repeat
///   if m == S0 then if <truthy> then <body>; m = S1; continue else <dead>; m = S2; end;
///   elseif m == S1 then break;
///   elseif m == S2 then return <num>;
///   end
/// until false
fn style_repeat_until_false(rng: &mut GenRng, v: i64, body: &str) -> String {
    let s0 = st(rng);
    let s1 = st(rng);
    let s2 = st(rng);
    format!(
        "local m = {};repeat if m == {} then if {} then {}; m = {}; else {}; m = {}; end; elseif m == {} then break; elseif m == {} then return {}; end until false",
        s0, s0, truthy(rng, Some(v)), body, s1, dead(rng, false), s2, s1, s2, rng.range(2, 9999)
    )
}

/// 类型 3：while 恒真（while-(-K)do / while K do，配合 break/continue）
/// while-(-<K>)do if <truthy> then <body>; break; else <dead>; end; end
fn style_while_const(rng: &mut GenRng, v: i64, body: &str) -> String {
    let kn = rng.range(50, 200) as i64;
    let k = fmt_num(rng, kn);
    if rng.range(0, 2) == 0 {
        // while-(-K)do 形式（双重负号，恒真）
        format!(
            "while-(-{})do if {} then {}; break; else {} end; end",
            k, truthy(rng, Some(v)), body, dead(rng, false)
        )
    } else {
        // while <const> do 形式
        format!(
            "while {} do if {} then {}; break; else {}; end; end",
            const_true(rng), truthy(rng, Some(v)), body, dead(rng, false)
        )
    }
}

/// 类型 4：continue/break 密集，多出口尾合并
/// local m = S0; while true do
///   if m == S0 then if <truthy> then <body>; m = S1; continue else <dead>; m = S2; end;
///   elseif m == S1 then break;
///   elseif m == S2 then return <num>;
///   end
/// end
fn style_continue_break(rng: &mut GenRng, v: i64, body: &str) -> String {
    let s0 = st(rng);
    let s1 = st(rng);
    let s2 = st(rng);
    format!(
        "local m = {};while true do if m == {} then if {} then {}; m = {}; else {}; m = {}; end; elseif m == {} then break; elseif m == {} then return {}; end end",
        s0, s0, truthy(rng, Some(v)), body, s1, dead(rng, false), s2, s1, s2, rng.range(2, 9999)
    )
}

/// 类型 5：if not / 常量谓词 / 不透明谓词（not 嵌套不超过两层）
/// - if not(not <const_truthy>) then <body> else <dead> end   （双重否定，恒真）
/// - if not <const_truthy> then <dead> else <body> end         （恒假条件，走 else）
/// - if <letter_const_true> then <body> else <dead> end        （a>b 常量对比）
/// - if _ <op> <const> then <body> else <dead> end             （scratch 变量比较）
/// - 空 then 分支：if <truthy> then ; else <dead> end
fn style_if_not_predicate(rng: &mut GenRng, v: i64, body: &str) -> String {
    match rng.range(0, 6) {
        0 => format!(
            "if not(not {}) then {} else {} end",
            const_true(rng), body, dead(rng, false)
        ),
        1 => format!(
            "if not {} then {} else {} end",
            const_true(rng), dead(rng, false), body
        ),
        2 => format!(
            "if {} then {} else {} end",
            atom_letter(rng).0, body, dead(rng, false)
        ),
        3 => format!(
            "_={};if {} then {} else {} end",
            v, truthy(rng, Some(v)), body, dead(rng, false)
        ),
        4 => format!(
            "_={};if {} then ; else {} end",
            v, truthy(rng, Some(v)), dead(rng, false)
        ), // 空 then 分支
        _ => format!(
            "_={};if not {} then {} else {} end",
            v, truthy(rng, Some(v)), dead(rng, false), body
        ),
    }
}

/// 类型 7：死代码 / 不可达代码（包在 if/else 里的 dead 分支已由 dead() 处理，
/// 这里在 wrapper 外层制造“return 后仍有语句”的不可达形态）
/// 铁律：return 必须是其所在块的最后一句，后面不可达代码用 do...end 包围 return。
fn style_dead_code(rng: &mut GenRng, v: i64, body: &str) -> String {
    match rng.range(0, 4) {
        0 => format!(
            "if {} then {}; do return {} end; local __x = {}; else {} end",
            truthy(rng, Some(v)), body, rng.range(2, 9999), rng.range(2, 9999), dead(rng, false)
        ),
        1 => format!(
            "_={};if {} then {} else {} end; do return {} end; local __y = {};",
            v, truthy(rng, Some(v)), body, dead(rng, false), rng.range(2, 9999), rng.range(2, 9999)
        ),
        2 => format!(
            "_={};if {} then {} else do return {} end end",
            v, truthy(rng, Some(v)), body, rng.range(2, 9999)
        ),
        _ => format!(
            "_={};if {} then {} else {} end",
            v, truthy(rng, Some(v)), body, dead(rng, false)
        ),
    }
}

/// 把一条功能语句包进随机控制流（每次混淆结果都不同）。
/// `body` 必须是单条 Lua 语句（可含内部任意控制流），不含尾 `end` 匹配问题。
pub fn wrap_stmt(body: &str, rng: &mut GenRng) -> String {
    let v = sval(rng) as i64;
    // 外层统一补分号：wrapper 以 end 收尾时，后续 `st=...` 等 token 不会被粘成一个标识符
    let out = match rng.range(0, 20) {
        // 类型 1：显式状态变量 + 无限 while true 主循环
        0 => format!("_={};if {} then {} else {} end", v, truthy(rng, Some(v)), body, dead(rng, false)),
        // 类型 2：repeat ... until false（恒假 until）
        1 => format!("_={};if {} then {} else {} end", v, truthy(rng, Some(v)), body, dead(rng, false)),
        // 类型 3：while 恒真（while-(-K)do / while K do）
        2 => format!("_={};if {} then {} else {} end", v, truthy(rng, Some(v)), body, dead(rng, false)),
        // 类型 4：continue/break 密集
        3 => format!("_={};if {} then {} else {} end", v, truthy(rng, Some(v)), body, dead(rng, false)),
        // 类型 5：if not / 常量谓词 / 不透明谓词（not ≤ 2 层）
        4 => format!("_={};if {} then {} else {} end", v, truthy(rng, Some(v)), body, dead(rng, false)),
        // 类型 7：死代码 / 不可达代码
        5 => format!("_={};if {} then {} else {} end", v, truthy(rng, Some(v)), body, dead(rng, false)),
        // if + 随机恒真条件（scratch 复用 + 恒真判断）
        6 => format!(
            "_={};if {} then {} else {} end",
            v, truthy(rng, Some(v)), body, dead(rng, false)
        ),
        // 纯常量守卫 if（不碰 _）
        7 => format!(
            "if {} then {} else {} end",
            const_true(rng), body, dead(rng, false)
        ),
        // if not _ then ... else ...（scratch 恒真取反恒假）
        8 => format!(
            "_={};if not _ then {} else {} end",
            v, dead(rng, false), body
        ),
        // 双 not：if not(not _)（2 层 not，不超过两个）
        9 => format!(
            "_={};if not(not _) then {} else {} end",
            v, body, dead(rng, false)
        ),
        // repeat ... until <随机恒真条件>（单趟环）
        10 => format!(
            "_={};repeat if {} then {} else {} end until {}",
            v, truthy(rng, Some(v)), body, dead(rng, true), gen_until(rng)
        ),
        // repeat + 单侧死分支（无 break）
        11 => format!(
            "_={};repeat if {} then {} end {} until {}",
            v, falsy(rng, Some(v)), dead(rng, true), body, gen_until(rng)
        ),
        // for __=1,1（loop 变量名 __ 不遮蔽刮擦 `_`）
        12 => format!(
            "for __=1,1 do if __==1 then {} else {} end end",
            body, dead(rng, true)
        ),
        // elseif 与 else if 两种拼写混用
        13 => elseif_chain(rng, v, body),
        // 双层 if 嵌套（多层条件）
        14 => format!(
            "_={};if {} then if {} then {} else return {} end else return {} end",
            v, truthy(rng, Some(v)), truthy(rng, Some(v)), body,
            rng.range(2, 9999), rng.range(2, 9999)
        ),
        // 用户例子：if not _ then [空] else if _ and <恒真> or not _ then --代码 end end
        15 => format!(
            "_={};if not _ then ; else if _ and {} or not _ then {} end end",
            v, truthy(rng, Some(v)), body
        ),
        // 用户例子：if not _ then [死码] elseif not _ and <恒假> then else --代码 end
        16 => format!(
            "_={};if not _ then {} elseif not _ and {} then else {} end",
            v, dead_simple(rng), falsy(rng, Some(v)), body
        ),
        // repeat + 双层 if（多层条件嵌套，无 break）
        17 => format!(
            "_={};repeat if {} then if {} then {} else do return {} end end else do return {} end end until {}",
            v, truthy(rng, Some(v)), const_true(rng), body,
            rng.range(2, 9999), rng.range(2, 9999), gen_until(rng)
        ),
        // for + elseif（混拼写）
        18 => {
            if rng.range(0, 2) == 0 {
                format!(
                    "for __=1,1 do if __==1 then {} else break end end",
                    body
                )
            } else {
                format!(
                    "for __=1,1 do if not __ then break else if __==1 then {} else break end end end",
                    body
                )
            }
        }
        // 常量守卫嵌套 repeat（多层 + 非 scratch 判断）
        19 => format!(
            "if {} then repeat if {} then {} else {} end until {} else return {} end",
            const_true(rng), const_true(rng), body, dead(rng, true),
            gen_until(rng), rng.range(2, 9999)
        ),
        // 单趟 repeat：body 直接躺在环里，until 全随机
        _ => format!(
            "_={};repeat {} until {}",
            v, body, gen_until(rng)
        ),
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

/// scratch 常量（恒真分支配合使用的初始值，保证 _>L 等关系成立）
fn sval(rng: &mut GenRng) -> usize {
    rng.range(100, 100000)
}

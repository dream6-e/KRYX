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

/// scratch 常量（恒真分支配合使用的初始值，保证 _>L 等关系成立）
fn sval(rng: &mut GenRng) -> usize {
    rng.range(100, 100000)
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

fn fmt_letter_cmp(rng: &mut GenRng, l1: &str, op: &str, l2: &str) -> String {
    // 偶尔在比较两侧加一点恒等算术噪音（a+0>b 之类），数学上不改变真假
    match rng.range(0, 4) {
        0 | 3 => format!("{}{}{}", l1, op, l2),
        1 => format!("({}+0){}{}", l1, op, l2),
        _ => format!("{}{}({}-0)", l1, op, l2),
    }
}

/// `_` 相关的原子判断（真假按 v 精确推算）
fn atom_underscore(rng: &mut GenRng, v: i64) -> (String, bool) {
    match rng.range(0, 5) {
        // 与任意随机常数直接比较（如 _>5031）
        0 => {
            let b = rng.range(0, (v * 2) as usize) as i64;
            let op = pick_op(rng);
            (format!("_{}{}", op, b), cmp_val(v, b, op))
        }
        // 带加法噪音的比较（如 (_+7)>=200）
        1 => {
            let k = rng.range(1, 30) as i64;
            let b = rng.range(0, (v + k + 999) as usize) as i64;
            let op = pick_op(rng);
            (format!("(_+{}){}{}", k, op, b), cmp_val(v + k, b, op))
        }
        // 取模判余（如 _%7==3）
        2 => {
            let m = rng.range(3, 97) as i64;
            let r = rng.range(0, m as usize) as i64;
            let op = if rng.range(0, 2) == 0 { "==" } else { "~=" };
            (format!("_%{}{}{}", m, op, r), cmp_val(v % m, r, op))
        }
        // 乘法比较（如 (3*_)>120）
        3 => {
            let m = [2i64, 3, 5, 7][rng.range(0, 4)];
            let b = rng.range(0, (v * m) as usize + 1) as i64;
            let op = pick_op(rng);
            (format!("({}*_){}{}", m, op, b), cmp_val(v * m, b, op))
        }
        // 与小常数直接比较（老式 _>42 形态）
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

        let mut leaves: Vec<(String, bool)> = Vec::with_capacity(n_leaves);
        for _ in 0..n_leaves {
            let leaf_v = if want_underscore { v } else {
                // 这个原子不强制用 `_`，按原子级 60/40 规则
                if v.is_some() && rng.range(0, 10) < 6 { v } else { None }
            };
            let (txt, tr) = atom(rng, leaf_v);
            let nots = rng.range(0, 4); // 0..2 层 not
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
            expr = format!("not({})", expr);
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

/// 死分支：永不执行。return 随机数字/变量，或 loop 上下文里 break。
fn dead(rng: &mut GenRng, in_loop: bool) -> String {
    if in_loop && rng.range(0, 10) < 3 {
        if rng.range(0, 2) == 0 {
            return "break".into();
        }
        return format!("return {}", rng.range(2, 9999));
    }
    match rng.range(0, 4) {
        0 => format!("return {}", rng.range(2, 9999)),
        1 => format!("do _ = {}; return _ end", rng.range(2, 9999)),
        2 => "return _".into(),
        _ => format!("return {} + {}", rng.range(2, 999), rng.range(2, 999)),
    }
}

/// elseif 与 else if 两种拼写混用：随机构造链
fn elseif_chain(rng: &mut GenRng, v: i64, body: &str) -> String {
    let use_elseif = rng.range(0, 2) == 0;
    if use_elseif {
        format!(
            "_={};if {} then {} elseif {} then {} else {} end",
            v,
            falsy(rng, Some(v)),
            dead(rng, false),
            truthy(rng, Some(v)),
            body,
            dead(rng, false)
        )
    } else {
        format!(
            "_={};if {} then {} else if {} then {} else {} end end",
            v,
            falsy(rng, Some(v)),
            dead(rng, false),
            truthy(rng, Some(v)),
            body,
            dead(rng, false)
        )
    }
}

/// 把一条功能语句包进随机控制流（每次混淆结果都不同）。
/// `body` 必须是单条 Lua 语句（可含内部任意控制流），不含尾 `end` 匹配问题。
pub fn wrap_stmt(body: &str, rng: &mut GenRng) -> String {
    let v = sval(rng) as i64;
    // sample2 最核心的控制流形态：哨兵状态码 + `repeat ... until false` +
    // `continue`/`break` 出口。约 35% 的语句走这条路径，其余走下面的
    // if/repeat/for 单趟包裹。
    // 状态机在 BODY 之后还要补 `break;`，所以 BODY 自身不能已经带走控制流
    //（`return` / `break` / `continue` 都必须是块的最后一条语句，后面不能再接东西）。
    let body_has_jump = body
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "return" || w == "break" || w == "continue");
    if !body_has_jump && rng.range(0, 100) < 40 {
        return state_machine(body, rng);
    }
    // 外层统一补分号：wrapper 以 end 收尾时，后续 `st=...` 等 token 不会被粘成一个标识符
    let out = match rng.range(0, 20) {
        // if + 随机恒真条件（scratch 复用 + 恒真判断）
        0 => format!(
            "_={};if {} then {} else {} end",
            v,
            truthy(rng, Some(v)),
            body,
            dead(rng, false)
        ),
        // 纯常量守卫 if（不碰 _）
        1 => format!(
            "if {} then {} else {} end",
            const_true(rng),
            body,
            dead(rng, false)
        ),
        // if not _ then ... else ...（scratch 恒真取反恒假）
        2 => format!(
            "_={};if not _ then {} else {} end",
            v,
            dead(rng, false),
            body
        ),
        // 双 not：if not(not _)
        3 => format!(
            "_={};if not(not _) then {} else {} end",
            v,
            body,
            dead(rng, false)
        ),
        // repeat ... until <随机恒真条件>（单趟环，不再固定 not nil）
        4 => format!(
            "_={};repeat if {} then {} else {} end until {}",
            v,
            truthy(rng, Some(v)),
            body,
            dead(rng, true),
            gen_until(rng)
        ),
        // repeat + 单侧死分支（无 break）
        5 => format!(
            "_={};repeat if {} then {} end {} until {}",
            v,
            falsy(rng, Some(v)),
            dead(rng, true),
            body,
            gen_until(rng)
        ),
        // for __=1,1（loop 变量名不能遮蔽刮擦 `_` —— BODY 里的 `_` 必须绑定到 entry hoist 的 upvalue）
        6 => format!(
            "for __=1,1 do if __==1 then {} else {} end end",
            body,
            dead(rng, true)
        ),
        // elseif 与 else if 两种拼写混用（随机构造链）
        7 => elseif_chain(rng, v, body),
        // 双层 if 嵌套（多层条件）
        8 => format!(
            "_={};if {} then if {} then {} else return {} end else return {} end",
            v,
            truthy(rng, Some(v)),
            truthy(rng, Some(v)),
            body,
            rng.range(2, 9999),
            rng.range(2, 9999)
        ),
        // 用户例子：if not _ then else if _ and <恒真> or not _ then --代码 end end
        9 => format!(
            "_={};if not _ then else if _ and {} or not _ then {} end end",
            v,
            truthy(rng, Some(v)),
            body
        ),
        // 用户例子：if not _ then elseif not _ and <恒假> then else --代码 end
        10 => format!(
            "_={};if not _ then elseif not _ and {} then else {} end",
            v,
            falsy(rng, Some(v)),
            body
        ),
        // 用户例子：repeat a==2 and nil 风格（左侧 _==v 恒真、链上随机恒假原子）
        11 => format!(
            "_={};repeat if _=={} and {} then else if {} then {} else break end end until {}",
            v,
            v,
            falsy(rng, Some(v)),
            truthy(rng, Some(v)),
            body,
            gen_until(rng)
        ),
        // repeat + 双层 if（多层条件嵌套，无 break）
        12 => format!(
            "_={};repeat if {} then if {} then {} else do return {} end end else do return {} end end until {}",
            v,
            truthy(rng, Some(v)),
            const_true(rng),
            body,
            rng.range(2, 9999),
            rng.range(2, 9999),
            gen_until(rng)
        ),
        // for + elseif（混拼写）
        13 => {
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
        14 => format!(
            "if {} then repeat if {} then {} else {} end until {} else return {} end",
            const_true(rng),
            const_true(rng),
            body,
            dead(rng, true),
            gen_until(rng),
            rng.range(2, 9999)
        ),
        // 单趟 repeat：body 直接躺在环里，until 全随机
        15 => format!(
            "_={};repeat {} until {}",
            v,
            body,
            gen_until(rng)
        ),
        // 三层嵌套 if（字母常量比较在里面随机出现）
        16 => format!(
            "_={};if {} then if {} then if {} then {} else do return {} end end else do return {} end end else do return {} end end",
            v,
            truthy(rng, Some(v)),
            truthy(rng, None),
            truthy(rng, Some(v)),
            body,
            rng.range(2, 9999),
            rng.range(2, 9999),
            rng.range(2, 9999)
        ),
        // if <恒假> then dead else BODY end（反写单侧）
        17 => format!(
            "if {} then {} else {} end",
            falsy(rng, None),
            dead(rng, false),
            body
        ),
        // for + repeat 嵌套（两层循环 + 随机 until）
        18 => format!(
            "for __=1,1 do repeat {} until {} end",
            body,
            gen_until(rng)
        ),
        // 双包裹：if <字母常量恒真> then repeat BODY until <随机> end
        19 => format!(
            "if {} then repeat {} until {} end",
            const_true(rng),
            body,
            gen_until(rng)
        ),
        // 双层 repeat（嵌套单趟环）
        _ => format!(
            "_={};repeat repeat {} until {} until {}",
            v,
            body,
            gen_until(rng),
            gen_until(rng)
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

/// 状态字面量：`0x`/`0X`/`0b`/`0B`/十进制混用，含前导零与 `_`（与 sample2 一致）
fn state_lit(rng: &mut GenRng, v: u32) -> String {
    if rng.range(0, 100) < 12 {
        // 表达式通胀：`-(-0x..)` 这类
        let inner = state_lit_plain(rng, v);
        return format!("-(-{})", inner);
    }
    state_lit_plain(rng, v)
}

fn state_lit_plain(rng: &mut GenRng, v: u32) -> String {
    match rng.range(0, 3) {
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
    const VARS: [&str; 6] = ["W", "m", "h", "u", "Z", "L"];
    let var = VARS[rng.range(0, 6)].to_string();
    let n = rng.range(3, 6);
    let mut states: Vec<u32> = Vec::with_capacity(n);
    while states.len() < n {
        let v = rng.range(2, 200) as u32;
        if !states.contains(&v) {
            states.push(v);
        }
    }
    let body_idx = if rng.range(0, 100) < 70 { n - 1 } else { n - 2 };
    let use_elseif = rng.range(0, 2) == 0;

    let mut out = String::with_capacity(body.len() + 320);
    // sample2 里 37 处 `while true do` 就是字面 `true`；另有 `while-(-0B1011110)do`
    // 这类不透明恒真写法。两种混用。
    let guard = match rng.range(0, 10) {
        0..=5 => "true".to_string(),
        6..=7 => state_lit(rng, 1),
        8 => format!("not({})", falsy(rng, None)),
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
    const VARS: [&str; 6] = ["W", "m", "h", "u", "Z", "L"];
    let var = VARS[rng.range(0, 6)].to_string();
    let n = rng.range(3, 6);
    let mut states: Vec<u32> = Vec::with_capacity(n);
    while states.len() < n {
        let v = rng.range(2, 200) as u32;
        if !states.contains(&v) {
            states.push(v);
        }
    }
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

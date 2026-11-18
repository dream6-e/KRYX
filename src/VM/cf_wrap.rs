// 解码器控制流混淆：把每条功能语句包进随机化的控制流
//
// 原则（用户 2026-11-17 指示）：
// - 多用 repeat/while/for 代替裸 if；elseif 与 else if 混用
// - 条件里 60% 左右引用 scratch 变量 `_`（解码器入口统一 hoist 一个 upvalue `_`，全程复用）
// - 多层嵌套判断，不要单层 if 裸奔
// - 不走的分支用 break / return 随机数字或变量
// - 判断用 not / and / or 组合，scratch 变量复用，尽量少声明 local
//
// 正确性铁律：
// - 每个 wrapper 执行 BODY 恰好一次，且不依赖 `_` 的循环守卫必须是常量表达式
// - 真实循环（m_bxor / m_next / 初始化循环）的守卫只能用 const_true，不能引用 `_`
// - DEAD 分支永远不执行（条件恒真/恒假由常量保证），其中的 return/break 仅需语法合法
use crate::VM::VM_Backend::Generator::GenRng;

/// scratch 常量（恒真分支配合使用的初始值，保证 _>L 等关系成立）
fn sval(rng: &mut GenRng) -> usize {
    rng.range(100, 100000)
}

/// 与 scratch 配合的恒真判断：60% 用 `_`（scratch 已由 wrapper 置为 sval，L < 100），
/// 40% 用纯常量表达式（不碰 `_`）。
fn guard_true(rng: &mut GenRng) -> String {
    if rng.range(0, 10) < 6 {
        let l = rng.range(0, 60);
        match rng.range(0, 8) {
            0 => format!("_>{}", l),
            1 => "_>=100".into(),
            2 => "_~=0".into(),
            3 => format!("not(_<{})", l),
            4 => "(_+1)>1".into(),
            5 => "_==_".into(),
            6 => format!("not(_=={})", l),
            _ => "_%2==0 or _%2==1".into(),
        }
    } else {
        const_true(rng)
    }
}

/// 恒真常量表达式（不涉及 `_`），用于真实循环守卫与嵌套内层判断
pub fn const_true(rng: &mut GenRng) -> String {
    let a = rng.range(10, 900);
    let b = rng.range(1, a - 1);
    match rng.range(0, 8) {
        0 => format!("{}>{}", a, b),
        1 => format!("{}=={}", a, a),
        2 => format!("({}+{})>{}", a, 1, a),
        3 => format!("{}~={}", a, b),
        4 => "not nil".into(),
        5 => "true".into(),
        // 保证恒真：2a > a+1（a>=10）
        6 => format!("({}*2)>{}", a, a + 1),
        _ => format!("not({}<{})", a, b),
    }
}

/// 恒假判断（60% 基于 `_`，与 guard_true 对称；wrapper 已先把 `_` 置为 >=100）
pub fn guard_false(rng: &mut GenRng) -> String {
    if rng.range(0, 10) < 6 {
        match rng.range(0, 5) {
            0 => format!("_<{}", rng.range(0, 50)),
            1 => "_==0".into(),
            2 => "not(_>=100)".into(),
            3 => "not(_>60)".into(),
            _ => "not((_+1)>1)".into(),
        }
    } else {
        const_false(rng)
    }
}

/// 恒假常量表达式（不涉及 `_`）
#[allow(dead_code)]
pub fn const_false(rng: &mut GenRng) -> String {
    let a = rng.range(10, 900);
    let b = rng.range(a + 1, a + 1000);
    match rng.range(0, 5) {
        0 => format!("{}>{}", a, b),
        1 => format!("{}=={}", a, b),
        2 => format!("({}+{})<{}", a, 1, a),
        3 => "false".into(),
        _ => "not true".into(),
    }
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

/// 把一条功能语句包进随机控制流（每次混淆结果都不同）。
/// `body` 必须是单条 Lua 语句（可含内部任意控制流），不含尾 `end` 匹配问题。
pub fn wrap_stmt(body: &str, rng: &mut GenRng) -> String {
    let v = sval(rng);
    // 外层统一补分号：wrapper 以 end 收尾时，后续 `st=...` 等 token 不会被粘成一个标识符
    let out = match rng.range(0, 15) {
        // 数值 if：_ 复用 + 恒真判断
        0 => format!(
            "_={};if {} then {} else {} end",
            v,
            guard_true(rng),
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
        // if not _ then ... else ... （scratch 恒真取反恒假）
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
        // repeat ... until not nil（单趟环）
        4 => format!(
            "_={};repeat if {} then {} else {} end until not nil",
            v,
            guard_true(rng),
            body,
            dead(rng, true)
        ),
        // repeat ... until not nil（单趟环，死分支单侧 if，无 break）
        5 => format!(
            "_={};repeat if {} then {} end {} until not nil",
            v,
            guard_false(rng),
            dead(rng, true),
            body
        ),
        // for _=1,1（scratch 兼作循环变量，极致复用）
        6 => format!(
            "for _=1,1 do if _==1 then {} else {} end end",
            body,
            dead(rng, true)
        ),
        // elseif 与 else if 两种拼写混用
        7 => {
            if rng.range(0, 2) == 0 {
                format!(
                    "_={};if not _ then {} elseif _ or true then {} else {} end",
                    v,
                    dead(rng, false),
                    body,
                    dead(rng, false)
                )
            } else {
                format!(
                    "_={};if not _ then {} else if _ or true then {} else {} end end",
                    v,
                    dead(rng, false),
                    body,
                    dead(rng, false)
                )
            }
        }
        // 双层 if 嵌套（多层条件）
        8 => format!(
            "_={};if {} then if _~={} then {} else return {} end else return {} end",
            v,
            guard_true(rng),
            v + rng.range(1, 10000),
            body,
            rng.range(2, 9999),
            rng.range(2, 9999)
        ),
        // 用户例子：if not _ then else if _ and <t> or not _ then --代码 end end
        9 => format!(
            "_={};if not _ then else if _ and {} or not _ then {} end end",
            v,
            const_true(rng),
            body
        ),
        // 用户例子：if not _ then elseif not _ and <f> then else --代码 end
        10 => format!(
            "_={};if not _ then elseif not _ and {} then else {} end",
            v,
            const_false(rng),
            body
        ),
        // 用户例子：repeat a==2 and nil 风格（scratch 复用）
        11 => format!(
            "_=2;repeat if _==2 and nil then else if _>1 or _<3 then {} else break end end until not nil",
            body
        ),
        // repeat + 双层 if（多层条件嵌套，无 break）
        12 => format!(
            "_={};repeat if {} then if {} then {} else do return {} end end else do return {} end end until not nil",
            v,
            guard_true(rng),
            const_true(rng),
            body,
            rng.range(2, 9999),
            rng.range(2, 9999)
        ),
        // for + elseif（混拼写）
        13 => {
            if rng.range(0, 2) == 0 {
                format!(
                    "for _=1,1 do if _==1 then {} else break end end",
                    body
                )
            } else {
                format!(
                    "for _=1,1 do if not _ then break else if _==1 then {} else break end end end",
                    body
                )
            }
        }
        // 常量守卫嵌套 repeat（多层 + 非 scratch 判断）
        _ => format!(
            "if {} then repeat if {} then {} else {} end until not nil else return {} end",
            const_true(rng),
            const_true(rng),
            body,
            dead(rng, true),
            rng.range(2, 9999)
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

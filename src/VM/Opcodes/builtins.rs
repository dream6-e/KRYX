// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub const BUILTIN_NAMES: &[&str] = &[
    "print", "type", "tostring", "tonumber", "pairs", "ipairs", "next", "select",
    "unpack", "pcall", "xpcall", "error", "assert", "setmetatable", "getmetatable",
    "rawget", "rawset", "rawequal", "rawlen", "require", "collectgarbage", "loadstring",
    "newproxy", "game", "workspace", "script", "wait", "spawn", "delay", "tick",
    "typeof", "warn", "task", "math", "string", "table", "coroutine", "os", "debug",
    "bit32", "utf8", "shared", "_G", "Instance", "Enum", "Vector3", "CFrame", "Color3",
    "UDim2", "Vector2",
];

pub const BUILTIN_OP_BASE: usize = 90;
pub const BUILTIN_OP_COUNT: usize = BUILTIN_NAMES.len();
/// Phase 3：全局槽位化 opcode 伪类型（GetGlobalSlot/SetGlobalSlot 的 opcode 组号基址）。
/// 只出现在 Generator 产物中，不占用原始字节码 opcode 编号（原始编号 0..89）。
pub const GLOBAL_SLOT_OP_BASE: usize = BUILTIN_OP_BASE + BUILTIN_OP_COUNT;
pub const GLOBAL_SLOT_OP_COUNT: usize = 2;
pub const GLOBAL_GET_SLOT: usize = GLOBAL_SLOT_OP_BASE;
pub const GLOBAL_SET_SLOT: usize = GLOBAL_SLOT_OP_BASE + 1;
pub const TOTAL_OPCODES: usize = BUILTIN_OP_BASE + BUILTIN_OP_COUNT + GLOBAL_SLOT_OP_COUNT;

pub fn slot_permutation(seed: u64) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..BUILTIN_NAMES.len()).collect();
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9E3779B97F4A7C15);
    for i in (1..perm.len()).rev() {
        let j = rng.random_range(0..=i);
        perm.swap(i, j);
    }
    perm
}

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng, perm: &[usize]) -> String {
    let mut out = String::new();
    for (i, _name) in BUILTIN_NAMES.iter().enumerate() {
        let slot = perm[i];
        let op_index = BUILTIN_OP_BASE + slot;
        let mapped = m.get(op_index).cloned().unwrap_or_default();
        let mut h = OpcodeBuilder::new(mapped, cfg, rng);
        let a = h.raw_inst(2);
        out.push_str(&h.build(&format!("{{STK}}[{}] = {{BUILTINREG}}[{}]", a, slot + 1)));
    }
    out
}

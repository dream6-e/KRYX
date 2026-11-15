// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use crate::BytecodeCompiler::ir::opcode::Opcode;

#[derive(Debug, Clone)]
pub enum VOpcode {
    Standard { original: Opcode, v_index: u16 },
    Mutated { a_part: u16, b_part: u16 },
    SuperOperator { sub_opcodes: Vec<Opcode>, v_index: u16 },
    FakeBranchTrap,
}

impl VOpcode {
    pub fn generate_mapping(_seed: u32) -> Self {
        VOpcode::FakeBranchTrap
    }
}
// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use crate::BytecodeCompiler::ir::opcode::Opcode;
use crate::BytecodeCompiler::virtualizer::vopcode::VOpcode;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub data: u32,
    pub opcode: Opcode,
    pub a: u8,
    pub b: i32,
    pub c: i32,
    pub line: i32,
    pub v_opcode: Option<VOpcode>,
    pub is_junk: bool,
}
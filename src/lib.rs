// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
#![allow(warnings)]

/*
 (c)KRYVEX Ob
 BY ssssss85
 Virtualization obfuscation
*/

#[allow(non_snake_case)]
pub mod compiler;

#[allow(non_snake_case)]
pub mod BytecodeCompiler;

#[allow(non_snake_case)]
pub mod VM;

pub mod compressor;
pub mod packer;
pub mod parenwrap;

/// 重复数字字面量提升成局部变量（用户 2026-11-18 的体积优化）
pub mod seq;
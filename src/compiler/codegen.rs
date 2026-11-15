// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::collections::HashMap;
use crate::compiler::error::{LuaError, LuaResult, SyntaxError};
use super::ast::Block;
use super::lexer::Lexer;
use super::parser;
use crate::compiler::instructions::{
    BITRK, Instruction, LFIELDS_PER_FLUSH, LUAI_MAXUPVALUES, LUAI_MAXVARS, MAXARG_BX, MAXARG_C,
    MAXINDEXRK, MAXSTACK, NO_JUMP, NO_REG, OpCode, is_k,
};
use crate::compiler::proto::{
    LocalVar, Proto, ProtoRef, VARARG_HASARG, VARARG_ISVARARG, VARARG_NEEDSARG,
};
use crate::compiler::value::Val;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] 
pub(crate) enum ExprKind {
    Void,
    Nil,
    True,
    False,
    K,
    KNum,
    Local,
    Upval,
    Global,
    Indexed,
    Jmp,
    Relocable,
    NonReloc,
    Call,
    VarArg,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExprContext {
    pub kind: ExprKind,
    pub info: i32,
    pub aux: i32,
    pub nval: f64,
    pub t: i32,
    pub f: i32,
}
impl ExprContext {
    fn void() -> Self {
        Self {
            kind: ExprKind::Void,
            info: 0,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    fn new(kind: ExprKind, info: i32) -> Self {
        Self {
            kind,
            info,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    fn number(val: f64) -> Self {
        Self {
            kind: ExprKind::KNum,
            info: 0,
            aux: 0,
            nval: val,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    fn has_jumps(&self) -> bool {
        self.t != self.f
    }
    fn is_numeral(&self) -> bool {
        self.kind == ExprKind::KNum && self.t == NO_JUMP && self.f == NO_JUMP
    }
}
#[derive(Debug, Clone)]
pub(crate) struct UpvalDesc {
    pub in_stack: bool,
    pub index: u8,
    pub name: String,
}
#[allow(dead_code)] 
struct BlockContext {
    num_active_vars: u8,
    has_upval: bool,
    is_breakable: bool,
    break_list: i32,
    continue_list: i32,
}
#[derive(Hash, Eq, PartialEq)]
enum ConstantKey {
    Num(u64),
    Bool(bool),
    Str(Vec<u8>),
}
#[allow(dead_code)] 
pub(crate) struct FuncState {
    pub proto: Proto,
    pub free_reg: u8,
    pub num_active_vars: u8,
    pub upvalues: Vec<UpvalDesc>,
    active_vars: Vec<u16>,
    blocks: Vec<BlockContext>,
    pub jpc: i32,
    pub last_target: i32,
    nil_k: Option<u32>,
    constant_index: HashMap<ConstantKey, u32>,
}
impl FuncState {
    fn new(source: &str) -> Self {
        Self {
            proto: Proto::new(source),
            free_reg: 0,
            num_active_vars: 0,
            upvalues: Vec::new(),
            active_vars: Vec::new(),
            blocks: Vec::new(),
            jpc: NO_JUMP,
            last_target: -1,
            nil_k: None,
            constant_index: HashMap::new(),
        }
    }
    pub(crate) fn pc(&self) -> usize {
        self.proto.code.len()
    }
}
pub struct Compiler {
    func_states: Vec<FuncState>,
    source_name: String,
    pub(crate) current_line: u32,
}
#[allow(dead_code)] 
impl Compiler {
    fn new(source_name: &str) -> Self {
        let fs = FuncState::new(source_name);
        Self {
            func_states: vec![fs],
            source_name: source_name.to_string(),
            current_line: 1,
        }
    }
    #[allow(clippy::expect_used)]
    pub(crate) fn fs(&self) -> &FuncState {
        self.func_states
            .last()
            .expect("compiler must have at least one function state")
    }
    #[allow(clippy::expect_used)]
    pub(crate) fn fs_mut(&mut self) -> &mut FuncState {
        self.func_states
            .last_mut()
            .expect("compiler must have at least one function state")
    }
    fn syntax_error(&self, msg: &str) -> LuaError {
        LuaError::Syntax(SyntaxError {
            message: msg.to_string(),
            source: self.source_name.clone(),
            line: self.current_line,
            raw_message: None,
        })
    }
    pub(crate) fn emit(&mut self, instr: Instruction, line: u32) -> usize {
        self.discharge_jpc();
        let fs = self.fs_mut();
        let pc = fs.proto.code.len();
        fs.proto.code.push(instr.raw());
        fs.proto.line_info.push(line);
        pc
    }
    pub(crate) fn emit_abc(&mut self, op: OpCode, a: u32, b: u32, c: u32, line: u32) -> usize {
        self.emit(Instruction::abc(op, a, b, c), line)
    }
    pub(crate) fn emit_nil(&mut self, from: u32, n: u32, line: u32) {
        let fs = self.fs();
        let pc = fs.pc();
        let last_target = fs.last_target;
        if (pc as i32) > last_target {
            if pc == 0 {
                return;
            }
            let prev = self.get_instruction(pc - 1);
            if prev.opcode() == OpCode::LoadNil {
                let pfrom = prev.a();
                let pto = prev.b();
                if pfrom <= from && from <= pto + 1 {
                    if from + n - 1 > pto {
                        let mut updated = prev;
                        updated.set_b(from + n - 1);
                        self.set_instruction(pc - 1, updated);
                    }
                    return;
                }
            }
        }
        self.emit_abc(OpCode::LoadNil, from, from + n - 1, 0, line);
    }
    pub(crate) fn emit_abx(&mut self, op: OpCode, a: u32, bx: u32, line: u32) -> usize {
        self.emit(Instruction::a_bx(op, a, bx), line)
    }
    #[allow(dead_code)]
    pub(crate) fn emit_asbx(&mut self, op: OpCode, a: u32, sbx: i32, line: u32) -> usize {
        self.emit(Instruction::a_sbx(op, a, sbx), line)
    }
    pub(crate) fn get_instruction(&self, pc: usize) -> Instruction {
        Instruction::from_raw(self.fs().proto.code[pc])
    }
    pub(crate) fn set_instruction(&mut self, pc: usize, instr: Instruction) {
        self.fs_mut().proto.code[pc] = instr.raw();
    }
    pub(crate) fn emit_jump(&mut self, line: u32) -> usize {
        let jpc = self.fs().jpc;
        let fs = self.fs_mut();
        fs.jpc = NO_JUMP;
        let pc = self.emit_asbx(OpCode::Jmp, 0, NO_JUMP, line);
        self.concat_jumps_result(pc, jpc)
    }
    pub(crate) fn patch_jump(&mut self, pc: usize, target: usize) {
        let offset = target as i32 - pc as i32 - 1;
        let mut instr = self.get_instruction(pc);
        instr.set_sbx(offset);
        self.set_instruction(pc, instr);
    }
    fn get_jump_target(&self, pc: usize) -> i32 {
        let offset = self.get_instruction(pc).sbx();
        if offset == NO_JUMP {
            return NO_JUMP;
        }
        (pc as i32) + 1 + offset
    }
    fn concat_jumps_result(&mut self, l1: usize, l2: i32) -> usize {
        if l2 == NO_JUMP {
            return l1;
        }
        let l1_i32 = l1 as i32;
        if l1_i32 == NO_JUMP {
            return l2 as usize;
        }
        let mut list = l1_i32;
        loop {
            let next = self.get_jump_target(list as usize);
            if next == NO_JUMP {
                self.patch_jump(list as usize, l2 as usize);
                break;
            }
            list = next;
        }
        l1
    }
    pub(crate) fn concat_jumps(&mut self, l1: &mut i32, l2: i32) {
        if l2 == NO_JUMP {
            return;
        }
        if *l1 == NO_JUMP {
            *l1 = l2;
        } else {
            let mut list = *l1;
            loop {
                let next = self.get_jump_target(list as usize);
                if next == NO_JUMP {
                    self.patch_jump(list as usize, l2 as usize);
                    break;
                }
                list = next;
            }
        }
    }
    pub(crate) fn patch_list(&mut self, list: i32, target: usize) {
        if target == self.fs().pc() {
            self.patch_to_here(list);
        } else {
            self.patch_list_aux(list, target, NO_REG, target);
        }
    }
    pub(crate) fn patch_to_here(&mut self, list: i32) {
        let jpc = self.fs().jpc;
        let mut merged = jpc;
        self.concat_jumps(&mut merged, list);
        self.fs_mut().jpc = merged;
    }
    fn discharge_jpc(&mut self) {
        let jpc = self.fs().jpc;
        if jpc != NO_JUMP {
            let pc = self.fs().pc();
            self.patch_list_aux(jpc, pc, NO_REG, pc);
            self.fs_mut().jpc = NO_JUMP;
        }
    }
    fn need_value(&self, mut list: i32) -> bool {
        while list != NO_JUMP {
            let ctrl = self.get_jump_control(list as usize);
            let instr = self.get_instruction(ctrl);
            if instr.opcode() != OpCode::TestSet {
                return true;
            }
            list = self.get_jump_target(list as usize);
        }
        false
    }
    fn patch_test_reg(&mut self, node: usize, reg: u32) -> bool {
        let ctrl = self.get_jump_control(node);
        let instr = self.get_instruction(ctrl);
        if instr.opcode() != OpCode::TestSet {
            return false;
        }
        if reg != NO_REG && reg != instr.b() {
            let mut patched = instr;
            patched.set_a(reg);
            self.set_instruction(ctrl, patched);
        } else {
            let replacement = Instruction::abc(OpCode::Test, instr.b(), 0, instr.c());
            self.set_instruction(ctrl, replacement);
        }
        true
    }
    fn remove_values(&mut self, mut list: i32) {
        while list != NO_JUMP {
            self.patch_test_reg(list as usize, NO_REG);
            list = self.get_jump_target(list as usize);
        }
    }
    fn patch_list_aux(&mut self, mut list: i32, vtarget: usize, reg: u32, dtarget: usize) {
        while list != NO_JUMP {
            let next = self.get_jump_target(list as usize);
            if self.patch_test_reg(list as usize, reg) {
                self.patch_jump(list as usize, vtarget);
            } else {
                self.patch_jump(list as usize, dtarget);
            }
            list = next;
        }
    }
    fn code_label(&mut self, reg: u32, b: u32, jump: u32, line: u32) -> usize {
        self.get_label();
        self.emit_abc(OpCode::LoadBool, reg, b, jump, line)
    }
    pub(crate) fn add_constant(&mut self, val: Val) -> LuaResult<u32> {
        let key = match val {
            Val::Num(n) => ConstantKey::Num(n.to_bits()),
            Val::Bool(b) => ConstantKey::Bool(b),
            _ => {
                let fs = self.fs_mut();
                let idx = fs.proto.constants.len();
                if idx > MAXARG_BX as usize {
                    return Err(self.syntax_error("constant table overflow"));
                }
                fs.proto.constants.push(val);
                #[allow(clippy::cast_possible_truncation)]
                return Ok(idx as u32);
            }
        };
        let fs = self.fs_mut();
        if let Some(&idx) = fs.constant_index.get(&key) {
            return Ok(idx);
        }
        let idx = fs.proto.constants.len();
        if idx > MAXARG_BX as usize {
            return Err(self.syntax_error("constant table overflow"));
        }
        fs.proto.constants.push(val);
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u32;
        fs.constant_index.insert(key, idx);
        Ok(idx)
    }
    pub(crate) fn string_constant(&mut self, s: &[u8]) -> LuaResult<u32> {
        let key = ConstantKey::Str(s.to_vec());
        let fs = self.fs_mut();
        if let Some(&idx) = fs.constant_index.get(&key) {
            return Ok(idx);
        }
        let idx = fs.proto.constants.len();
        if idx > MAXARG_BX as usize {
            return Err(self.syntax_error("constant table overflow"));
        }
        fs.proto.constants.push(Val::Nil);
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u32;
        fs.proto.string_pool.push((idx, s.to_vec()));
        fs.constant_index.insert(key, idx);
        Ok(idx)
    }
    pub(crate) fn number_constant(&mut self, n: f64) -> LuaResult<u32> {
        self.add_constant(Val::Num(n))
    }
    pub(crate) fn nil_constant(&mut self) -> LuaResult<u32> {
        if let Some(idx) = self.fs().nil_k {
            return Ok(idx);
        }
        let fs = self.fs_mut();
        let idx = fs.proto.constants.len();
        if idx > MAXARG_BX as usize {
            return Err(self.syntax_error("constant table overflow"));
        }
        fs.proto.constants.push(Val::Nil);
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u32;
        self.fs_mut().nil_k = Some(idx);
        Ok(idx)
    }
    pub(crate) fn alloc_reg(&mut self) -> LuaResult<u32> {
        self.check_stack(1)?;
        let reg = u32::from(self.fs().free_reg);
        self.fs_mut().free_reg += 1;
        Ok(reg)
    }
    pub(crate) fn reserve_regs(&mut self, n: u32) -> LuaResult<()> {
        self.check_stack(n)?;
        self.fs_mut().free_reg += n as u8;
        Ok(())
    }
    pub(crate) fn free_reg(&mut self, reg: u32) {
        let fs = self.fs();
        if reg >= u32::from(fs.num_active_vars) && !is_k(reg) {
            let fs = self.fs_mut();
            if u32::from(fs.free_reg) > 0 && reg == u32::from(fs.free_reg) - 1 {
                fs.free_reg -= 1;
            }
        }
    }
    fn check_stack(&mut self, n: u32) -> LuaResult<()> {
        let new_stack = u32::from(self.fs().free_reg) + n;
        if new_stack > MAXSTACK {
            return Err(self.syntax_error("function or expression too complex"));
        }
        let fs = self.fs_mut();
        if new_stack > u32::from(fs.proto.max_stack_size) {
            fs.proto.max_stack_size = new_stack as u8;
        }
        Ok(())
    }
    fn search_local(&self, name: &str) -> Option<u8> {
        let fs = self.fs();
        for i in (0..fs.num_active_vars).rev() {
            let var_idx = fs.active_vars[i as usize];
            if fs.proto.local_vars[var_idx as usize].name == name {
                return Some(i);
            }
        }
        None
    }
    fn search_upvalue(&self, name: &str) -> Option<u8> {
        let fs = self.fs();
        for (i, uv) in fs.upvalues.iter().enumerate() {
            if uv.name == name {
                #[allow(clippy::cast_possible_truncation)]
                return Some(i as u8);
            }
        }
        None
    }
    fn add_upvalue(
        &mut self,
        fs_idx: usize,
        name: &str,
        in_stack: bool,
        index: u8,
    ) -> LuaResult<u8> {
        let fs = &mut self.func_states[fs_idx];
        for (i, uv) in fs.upvalues.iter().enumerate() {
            if uv.in_stack == in_stack && uv.index == index {
                #[allow(clippy::cast_possible_truncation)]
                return Ok(i as u8);
            }
        }
        let idx = fs.upvalues.len();
        if idx >= LUAI_MAXUPVALUES as usize {
            return Err(self.syntax_error("too many upvalues"));
        }
        fs.upvalues.push(UpvalDesc {
            in_stack,
            index,
            name: name.to_string(),
        });
        fs.proto.num_upvalues = fs.upvalues.len() as u8;
        #[allow(clippy::cast_possible_truncation)]
        Ok(idx as u8)
    }
    pub(crate) fn resolve_var(&mut self, name: &str) -> LuaResult<ExprContext> {
        if let Some(reg) = self.search_local(name) {
            return Ok(ExprContext::new(ExprKind::Local, i32::from(reg)));
        }
        if let Some(idx) = self.search_upvalue(name) {
            return Ok(ExprContext::new(ExprKind::Upval, i32::from(idx)));
        }
        let current_idx = self.func_states.len() - 1;
        if current_idx > 0 {
            if let Some(uv_idx) = self.resolve_var_aux(current_idx, name)? {
                return Ok(ExprContext::new(ExprKind::Upval, i32::from(uv_idx)));
            }
        }
        let k = self.string_constant(name.as_bytes())?;
        Ok(ExprContext {
            kind: ExprKind::Global,
            info: k as i32,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        })
    }
    fn resolve_var_aux(&mut self, fs_idx: usize, name: &str) -> LuaResult<Option<u8>> {
        if fs_idx == 0 {
            return Ok(None); 
        }
        let parent_idx = fs_idx - 1;
        let parent_fs = &self.func_states[parent_idx];
        for i in (0..parent_fs.num_active_vars).rev() {
            let var_idx = parent_fs.active_vars[i as usize];
            if parent_fs.proto.local_vars[var_idx as usize].name == name {
                Self::mark_upval(&mut self.func_states[parent_idx], i);
                let uv_idx = self.add_upvalue(fs_idx, name, true, i)?;
                return Ok(Some(uv_idx));
            }
        }
        let parent_fs = &self.func_states[parent_idx];
        for (i, uv) in parent_fs.upvalues.iter().enumerate() {
            if uv.name == name {
                #[allow(clippy::cast_possible_truncation)]
                let uv_idx = self.add_upvalue(fs_idx, name, false, i as u8)?;
                return Ok(Some(uv_idx));
            }
        }
        if let Some(parent_uv) = self.resolve_var_aux(parent_idx, name)? {
            let uv_idx = self.add_upvalue(fs_idx, name, false, parent_uv)?;
            return Ok(Some(uv_idx));
        }
        Ok(None) 
    }
    pub(crate) fn new_local(&mut self, name: &str) -> LuaResult<u16> {
        let fs = self.fs_mut();
        if fs.active_vars.len() >= LUAI_MAXVARS as usize {
            return Err(self.syntax_error("too many local variables"));
        }
        let idx = fs.proto.local_vars.len();
        fs.proto.local_vars.push(LocalVar {
            name: name.to_string(),
            start_pc: 0,
            end_pc: 0,
        });
        #[allow(clippy::cast_possible_truncation)]
        let idx16 = idx as u16;
        fs.active_vars.push(idx16);
        Ok(idx16)
    }
    pub(crate) fn activate_locals(&mut self, n: u32) {
        let fs = self.fs_mut();
        let pc = fs.proto.code.len();
        let start_idx = fs.active_vars.len() - n as usize;
        for i in 0..n as usize {
            let var_idx = fs.active_vars[start_idx + i] as usize;
            if var_idx < fs.proto.local_vars.len() {
                fs.proto.local_vars[var_idx].start_pc = pc as u32;
            }
        }
        fs.num_active_vars += n as u8;
    }
    pub(crate) fn remove_locals(&mut self, to_level: u8) {
        let fs = self.fs_mut();
        let pc = fs.proto.code.len() as u32;
        while fs.num_active_vars > to_level {
            fs.num_active_vars -= 1;
            if let Some(var_idx) = fs.active_vars.pop() {
                if (var_idx as usize) < fs.proto.local_vars.len() {
                    fs.proto.local_vars[var_idx as usize].end_pc = pc;
                }
            }
        }
    }
    pub(crate) fn enter_block(&mut self, is_breakable: bool) {
        let num_active = self.fs().num_active_vars;
        self.fs_mut().blocks.push(BlockContext {
            num_active_vars: num_active,
            has_upval: false,
            is_breakable,
            break_list: NO_JUMP,
            continue_list: NO_JUMP,
        });
    }
    pub(crate) fn leave_block(&mut self) {
        if let Some(block) = self.fs_mut().blocks.pop() {
            self.remove_locals(block.num_active_vars);
            self.fs_mut().free_reg = self.fs().num_active_vars;
            if block.has_upval {
                let level = u32::from(block.num_active_vars);
                self.emit_abc(OpCode::Close, level, 0, 0, self.current_line);
            }
            if block.is_breakable {
                let pc = self.fs().pc();
                self.patch_list(block.break_list, pc);
            }
        }
    }
    fn mark_upval(fs: &mut FuncState, level: u8) {
        for block in fs.blocks.iter_mut().rev() {
            if block.num_active_vars <= level {
                block.has_upval = true;
                return;
            }
        }
    }
    pub(crate) fn add_break_jump(&mut self, jump_pc: i32) -> LuaResult<()> {
        let fs = self.fs_mut();
        for block in fs.blocks.iter_mut().rev() {
            if block.is_breakable {
                let mut bl = block.break_list;
                if bl == NO_JUMP {
                    block.break_list = jump_pc;
                } else {
                    loop {
                        let instr = Instruction::from_raw(fs.proto.code[bl as usize]);
                        let next_offset = instr.sbx();
                        if next_offset == NO_JUMP {
                            let offset = jump_pc - bl - 1;
                            let mut patched = instr;
                            patched.set_sbx(offset);
                            fs.proto.code[bl as usize] = patched.raw();
                            break;
                        }
                        bl = bl + 1 + next_offset;
                    }
                }
                return Ok(());
            }
        }
        Err(self.syntax_error("no loop to break"))
    }
    pub(crate) fn add_continue_jump(&mut self, jump_pc: i32) -> LuaResult<()> {
        let fs = self.fs_mut();
        for block in fs.blocks.iter_mut().rev() {
            if block.is_breakable {
                let mut bl = block.continue_list;
                if bl == NO_JUMP {
                    block.continue_list = jump_pc;
                } else {
                    loop {
                        let instr = Instruction::from_raw(fs.proto.code[bl as usize]);
                        let next_offset = instr.sbx();
                        if next_offset == NO_JUMP {
                            let offset = jump_pc - bl - 1;
                            let mut patched = instr;
                            patched.set_sbx(offset);
                            fs.proto.code[bl as usize] = patched.raw();
                            break;
                        }
                        bl = bl + 1 + next_offset;
                    }
                }
                return Ok(());
            }
        }
        Err(self.syntax_error("no loop to continue"))
    }
    pub(crate) fn discharge_vars(&mut self, e: &mut ExprContext, line: u32) {
        match e.kind {
            ExprKind::Local => {
                e.kind = ExprKind::NonReloc;
            }
            ExprKind::Upval => {
                let pc = self.emit_abc(OpCode::GetUpval, 0, e.info as u32, 0, line);
                e.info = pc as i32;
                e.kind = ExprKind::Relocable;
            }
            ExprKind::Global => {
                let pc = self.emit_abx(OpCode::GetGlobal, 0, e.info as u32, line);
                e.info = pc as i32;
                e.kind = ExprKind::Relocable;
            }
            ExprKind::Indexed => {
                let table_reg = e.info as u32;
                let key_rk = e.aux as u32;
                self.free_reg(key_rk);
                self.free_reg(table_reg);
                let pc = self.emit_abc(OpCode::GetTable, 0, table_reg, key_rk, line);
                e.info = pc as i32;
                e.kind = ExprKind::Relocable;
            }
            ExprKind::Call | ExprKind::VarArg => {
                self.set_one_ret(e);
            }
            _ => {} 
        }
    }
    fn set_one_ret(&mut self, e: &mut ExprContext) {
        if e.kind == ExprKind::Call {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_c(2);
            self.set_instruction(e.info as usize, instr);
            e.kind = ExprKind::NonReloc;
            #[allow(clippy::cast_possible_wrap)]
            {
                e.info = instr.a() as i32;
            }
        } else if e.kind == ExprKind::VarArg {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_b(2); 
            self.set_instruction(e.info as usize, instr);
            e.kind = ExprKind::Relocable;
        }
    }
    pub(crate) fn exp2nextreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        self.free_expr(e);
        let reg = self.alloc_reg()?;
        self.exp2reg(e, reg, line);
        Ok(())
    }
    pub(crate) fn exp2anyreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<u32> {
        self.discharge_vars(e, line);
        if e.kind == ExprKind::NonReloc {
            if !e.has_jumps() {
                return Ok(e.info as u32);
            }
            if e.info as u32 >= u32::from(self.fs().num_active_vars) {
                self.exp2reg(e, e.info as u32, line);
                return Ok(e.info as u32);
            }
        }
        self.exp2nextreg(e, line)?;
        Ok(e.info as u32)
    }
    #[allow(clippy::cast_sign_loss)]
    pub(crate) fn exp2reg(&mut self, e: &mut ExprContext, reg: u32, line: u32) {
        self.discharge2reg(e, reg, line);
        if e.kind == ExprKind::Jmp {
            let mut e_t = e.t;
            self.concat_jumps(&mut e_t, e.info);
            e.t = e_t;
        }
        if e.has_jumps() {
            let mut p_f = NO_JUMP; 
            let mut p_t = NO_JUMP; 
            if self.need_value(e.t) || self.need_value(e.f) {
                let fj = if e.kind == ExprKind::Jmp {
                    NO_JUMP
                } else {
                    self.emit_jump(line) as i32
                };
                p_f = self.code_label(reg, 0, 1, line) as i32; 
                p_t = self.code_label(reg, 1, 0, line) as i32; 
                self.patch_to_here(fj);
            }
            let final_pc = self.get_label();
            let dt_f = if p_f == NO_JUMP {
                final_pc
            } else {
                p_f as usize
            };
            let dt_t = if p_t == NO_JUMP {
                final_pc
            } else {
                p_t as usize
            };
            self.patch_list_aux(e.f, final_pc, reg, dt_f);
            self.patch_list_aux(e.t, final_pc, reg, dt_t);
        }
        e.f = NO_JUMP;
        e.t = NO_JUMP;
        e.info = reg as i32;
        e.kind = ExprKind::NonReloc;
    }
    fn discharge2reg(&mut self, e: &mut ExprContext, reg: u32, line: u32) {
        self.discharge_vars(e, line);
        match e.kind {
            ExprKind::Nil => {
                self.emit_nil(reg, 1, line);
            }
            ExprKind::False | ExprKind::True => {
                let bool_val = u32::from(e.kind == ExprKind::True);
                self.emit_abc(OpCode::LoadBool, reg, bool_val, 0, line);
            }
            ExprKind::K => {
                self.emit_abx(OpCode::LoadK, reg, e.info as u32, line);
            }
            ExprKind::KNum => {
                let k = self.number_constant(e.nval).unwrap_or(0); 
                self.emit_abx(OpCode::LoadK, reg, k, line);
            }
            ExprKind::Relocable => {
                let mut instr = self.get_instruction(e.info as usize);
                instr.set_a(reg);
                self.set_instruction(e.info as usize, instr);
            }
            ExprKind::NonReloc => {
                if reg != e.info as u32 {
                    self.emit_abc(OpCode::Move, reg, e.info as u32, 0, line);
                }
            }
            _ => {
                return;
            }
        }
        e.info = reg as i32;
        e.kind = ExprKind::NonReloc;
    }
    fn discharge2anyreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        if e.kind != ExprKind::NonReloc {
            self.reserve_regs(1)?;
            let reg = u32::from(self.fs().free_reg) - 1;
            self.discharge2reg(e, reg, line);
        }
        Ok(())
    }
    pub(crate) fn exp2rk(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<u32> {
        self.exp2val(e, line);
        match e.kind {
            ExprKind::True | ExprKind::False | ExprKind::Nil
                if self.fs().proto.constants.len() <= MAXINDEXRK as usize =>
            {
                let k = match e.kind {
                    ExprKind::Nil => self.nil_constant()?,
                    ExprKind::True => self.add_constant(Val::Bool(true))?,
                    _ => self.add_constant(Val::Bool(false))?, 
                };
                e.info = k as i32;
                e.kind = ExprKind::K;
                return Ok(k | BITRK);
            }
            ExprKind::K if (e.info as u32) <= MAXINDEXRK => {
                return Ok(e.info as u32 | BITRK);
            }
            ExprKind::KNum => {
                let k = self.number_constant(e.nval)?;
                if k <= MAXINDEXRK {
                    e.info = k as i32;
                    e.kind = ExprKind::K;
                    return Ok(k | BITRK);
                }
            }
            _ => {}
        }
        let reg = self.exp2anyreg(e, line)?;
        Ok(reg)
    }
    pub(crate) fn free_expr(&mut self, e: &ExprContext) {
        if e.kind == ExprKind::NonReloc {
            self.free_reg(e.info as u32);
        }
    }
    pub(crate) fn storevar(
        &mut self,
        var: &ExprContext,
        ex: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match var.kind {
            ExprKind::Local => {
                self.free_expr(ex);
                self.exp2reg(ex, var.info as u32, line);
            }
            ExprKind::Upval => {
                let e = self.exp2anyreg(ex, line)?;
                self.emit_abc(OpCode::SetUpval, e, var.info as u32, 0, line);
            }
            ExprKind::Global => {
                let e = self.exp2anyreg(ex, line)?;
                self.emit_abx(OpCode::SetGlobal, e, var.info as u32, line);
            }
            ExprKind::Indexed => {
                let e = self.exp2rk(ex, line)?;
                self.emit_abc(OpCode::SetTable, var.info as u32, var.aux as u32, e, line);
            }
            _ => {
                return Err(self.syntax_error("invalid assignment target"));
            }
        }
        self.free_expr(ex);
        Ok(())
    }
    pub(crate) fn compile_condition(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<i32> {
        if e.kind == ExprKind::Nil {
            e.kind = ExprKind::False;
        }
        self.goiftrue(e, line)?;
        Ok(e.f)
    }
    pub(crate) fn goiftrue(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        let pc = match e.kind {
            ExprKind::K | ExprKind::KNum | ExprKind::True => {
                NO_JUMP 
            }
            ExprKind::False => self.emit_jump(line) as i32,
            ExprKind::Jmp => {
                self.invertjump(e);
                e.info
            }
            _ => self.jumponcond(e, false, line)?,
        };
        let mut f = e.f;
        self.concat_jumps(&mut f, pc);
        e.f = f;
        self.patch_to_here(e.t);
        e.t = NO_JUMP;
        Ok(())
    }
    pub(crate) fn goiffalse(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        let pc = match e.kind {
            ExprKind::Nil | ExprKind::False => {
                NO_JUMP 
            }
            ExprKind::True => self.emit_jump(line) as i32,
            ExprKind::Jmp => e.info,
            _ => self.jumponcond(e, true, line)?,
        };
        let mut t = e.t;
        self.concat_jumps(&mut t, pc);
        e.t = t;
        self.patch_to_here(e.f);
        e.f = NO_JUMP;
        Ok(())
    }
    fn get_jump_control(&self, pc: usize) -> usize {
        if pc >= 1 {
            let prev = self.get_instruction(pc - 1);
            if prev.opcode().is_test_mode() {
                return pc - 1;
            }
        }
        pc
    }
    fn invertjump(&mut self, e: &ExprContext) {
        let jmp_pc = e.info as usize;
        let ctrl_pc = self.get_jump_control(jmp_pc);
        let mut instr = self.get_instruction(ctrl_pc);
        let a = instr.a();
        instr.set_a(u32::from(a == 0));
        self.set_instruction(ctrl_pc, instr);
    }
    fn jumponcond(&mut self, e: &mut ExprContext, cond: bool, line: u32) -> LuaResult<i32> {
        if e.kind == ExprKind::Relocable {
            let instr = self.get_instruction(e.info as usize);
            if instr.opcode() == OpCode::Not {
                self.fs_mut().proto.code.pop();
                self.fs_mut().proto.line_info.pop();
                let cond_val = u32::from(!cond);
                self.emit_abc(OpCode::Test, instr.b(), 0, cond_val, line);
                return Ok(self.emit_jump(line) as i32);
            }
        }
        self.discharge2anyreg(e, line)?;
        self.free_expr(e);
        let cond_val = u32::from(cond);
        self.emit_abc(OpCode::TestSet, NO_REG, e.info as u32, cond_val, line);
        Ok(self.emit_jump(line) as i32)
    }
    pub(crate) fn exp2val(&mut self, e: &mut ExprContext, line: u32) {
        if e.has_jumps() {
            drop(self.exp2anyreg(e, line));
        } else {
            self.discharge_vars(e, line);
        }
    }
    pub(crate) fn set_multret(&mut self, e: &mut ExprContext) {
        if e.kind == ExprKind::Call {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_c(0); 
            self.set_instruction(e.info as usize, instr);
        } else if e.kind == ExprKind::VarArg {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_b(0); 
            instr.set_a(u32::from(self.fs().free_reg));
            self.set_instruction(e.info as usize, instr);
            self.reserve_regs(1).ok(); 
            e.kind = ExprKind::Relocable;
        }
    }
    pub(crate) fn set_indexed(
        &mut self,
        table: &mut ExprContext,
        key: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        table.aux = self.exp2rk(key, line)? as i32;
        table.kind = ExprKind::Indexed;
        Ok(())
    }
    pub(crate) fn code_self(
        &mut self,
        e: &mut ExprContext,
        key: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        self.exp2anyreg(e, line)?;
        self.free_expr(e);
        let func = u32::from(self.fs().free_reg);
        self.reserve_regs(2)?;
        let key_rk = self.exp2rk(key, line)?;
        self.emit_abc(OpCode::OpSelf, func, e.info as u32, key_rk, line);
        self.free_expr(key);
        e.info = func as i32;
        e.kind = ExprKind::NonReloc;
        Ok(())
    }
    fn const_fold(op: OpCode, e1: &mut ExprContext, e2: &ExprContext) -> bool {
        if !e1.is_numeral() || !e2.is_numeral() {
            return false;
        }
        let v1 = e1.nval;
        let v2 = e2.nval;
        let r = match op {
            OpCode::Add => v1 + v2,
            OpCode::Sub => v1 - v2,
            OpCode::Mul => v1 * v2,
            OpCode::Div => {
                if v2 == 0.0 {
                    return false;
                }
                v1 / v2
            }
            OpCode::Mod => {
                if v2 == 0.0 {
                    return false;
                }
                (v1 / v2).floor().mul_add(-v2, v1)
            }
            OpCode::Pow => v1.powf(v2),
            OpCode::Unm => -v1,
            _ => return false,
        };
        if r.is_nan() {
            return false;
        }
        e1.nval = r;
        true
    }
    pub(crate) fn code_arith(
        &mut self,
        op: OpCode,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        if Self::const_fold(op, e1, e2) {
            return Ok(());
        }
        if op == OpCode::Concat {
            self.exp2nextreg(e2, line)?;
            self.exp2anyreg(e1, line)?;
        }
        let (b, c) = if op == OpCode::Unm || op == OpCode::Not || op == OpCode::Len {
            let b = self.exp2anyreg(e1, line)?;
            (b, 0)
        } else if op == OpCode::Concat {
            let b = e1.info as u32;
            let c = e2.info as u32;
            self.free_expr(e2);
            self.free_expr(e1);
            (b, c)
        } else {
            let c = self.exp2rk(e2, line)?;
            let b = self.exp2rk(e1, line)?;
            (b, c)
        };
        if op != OpCode::Concat {
            self.free_expr(e2);
            self.free_expr(e1);
        }
        e1.info = self.emit_abc(op, 0, b, c, line) as i32;
        e1.kind = ExprKind::Relocable;
        Ok(())
    }
    pub(crate) fn code_comp(
        &mut self,
        op: OpCode,
        cond: u32,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        let mut b = self.exp2rk(e1, line)?;
        let mut c = self.exp2rk(e2, line)?;
        self.free_expr(e2);
        self.free_expr(e1);
        let mut cond = cond;
        if cond == 0 && op != OpCode::Eq {
            std::mem::swap(&mut b, &mut c);
            cond = 1;
        }
        self.emit_abc(op, cond, b, c, line);
        let jmp = self.emit_jump(line);
        e1.info = jmp as i32;
        e1.kind = ExprKind::Jmp;
        e1.t = NO_JUMP;
        e1.f = NO_JUMP;
        Ok(())
    }
    pub(crate) fn infix(
        &mut self,
        op: super::ast::BinOp,
        e: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match op {
            super::ast::BinOp::And => {
                self.goiftrue(e, line)?;
            }
            super::ast::BinOp::Or => {
                self.goiffalse(e, line)?;
            }
            super::ast::BinOp::Concat => {
                self.exp2nextreg(e, line)?;
            }
            _ => {
                if !e.is_numeral() {
                    self.exp2rk(e, line)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn postfix(
        &mut self,
        op: super::ast::BinOp,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match op {
            super::ast::BinOp::And => {
                debug_assert!(e1.t == NO_JUMP);
                self.discharge_vars(e2, line);
                let mut f = e2.f;
                self.concat_jumps(&mut f, e1.f);
                e2.f = f;
                *e1 = *e2;
            }
            super::ast::BinOp::Or => {
                debug_assert!(e1.f == NO_JUMP);
                self.discharge_vars(e2, line);
                let mut t = e2.t;
                self.concat_jumps(&mut t, e1.t);
                e2.t = t;
                *e1 = *e2;
            }
            super::ast::BinOp::Concat => {
                self.exp2val(e2, line);
                if e2.kind == ExprKind::Relocable {
                    let instr = self.get_instruction(e2.info as usize);
                    if instr.opcode() == OpCode::Concat {
                        self.free_expr(e1);
                        let mut merged = self.get_instruction(e2.info as usize);
                        merged.set_b(e1.info as u32);
                        self.set_instruction(e2.info as usize, merged);
                        e1.kind = ExprKind::Relocable;
                        e1.info = e2.info;
                        return Ok(());
                    }
                }
                self.exp2nextreg(e2, line)?;
                self.code_arith(OpCode::Concat, e1, e2, line)?;
            }
            super::ast::BinOp::Add => self.code_arith(OpCode::Add, e1, e2, line)?,
            super::ast::BinOp::Sub => self.code_arith(OpCode::Sub, e1, e2, line)?,
            super::ast::BinOp::Mul => self.code_arith(OpCode::Mul, e1, e2, line)?,
            super::ast::BinOp::Div => self.code_arith(OpCode::Div, e1, e2, line)?,
            super::ast::BinOp::Mod => self.code_arith(OpCode::Mod, e1, e2, line)?,
            super::ast::BinOp::Pow => self.code_arith(OpCode::Pow, e1, e2, line)?,
            super::ast::BinOp::Eq => self.code_comp(OpCode::Eq, 1, e1, e2, line)?,
            super::ast::BinOp::Ne => self.code_comp(OpCode::Eq, 0, e1, e2, line)?,
            super::ast::BinOp::Lt => self.code_comp(OpCode::Lt, 1, e1, e2, line)?,
            super::ast::BinOp::Le => self.code_comp(OpCode::Le, 1, e1, e2, line)?,
            super::ast::BinOp::Gt => self.code_comp(OpCode::Lt, 0, e1, e2, line)?,
            super::ast::BinOp::Ge => self.code_comp(OpCode::Le, 0, e1, e2, line)?,
        }
        Ok(())
    }
    pub(crate) fn prefix(
        &mut self,
        op: super::ast::UnOp,
        e: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        let mut e2 = ExprContext::number(0.0);
        match op {
            super::ast::UnOp::Neg => {
                if e.kind == ExprKind::K {
                    self.exp2anyreg(e, line)?;
                }
                self.code_arith(OpCode::Unm, e, &mut e2, line)?;
            }
            super::ast::UnOp::Not => {
                self.code_not(e, line)?;
            }
            super::ast::UnOp::Len => {
                self.exp2anyreg(e, line)?;
                self.code_arith(OpCode::Len, e, &mut e2, line)?;
            }
        }
        Ok(())
    }
    fn code_not(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        match e.kind {
            ExprKind::Nil | ExprKind::False => {
                e.kind = ExprKind::True;
            }
            ExprKind::K | ExprKind::KNum | ExprKind::True => {
                e.kind = ExprKind::False;
            }
            ExprKind::Jmp => {
                self.invertjump(e);
            }
            ExprKind::Relocable | ExprKind::NonReloc => {
                self.discharge2anyreg(e, line)?;
                self.free_expr(e);
                e.info = self.emit_abc(OpCode::Not, 0, e.info as u32, 0, line) as i32;
                e.kind = ExprKind::Relocable;
            }
            _ => {} 
        }
        std::mem::swap(&mut e.t, &mut e.f);
        self.remove_values(e.f);
        self.remove_values(e.t);
        Ok(())
    }
    pub(crate) fn get_label(&mut self) -> usize {
        let pc = self.fs().pc();
        self.fs_mut().last_target = pc as i32;
        pc
    }
    pub(crate) fn code_setlist(&mut self, base: u32, nelems: u32, tostore: u32, line: u32) {
        let c = (nelems - 1) / LFIELDS_PER_FLUSH + 1;
        let b = if tostore == 0 { 0 } else { tostore };
        if c <= MAXARG_C {
            self.emit_abc(OpCode::SetList, base, b, c, line);
        } else {
            self.emit_abc(OpCode::SetList, base, b, 0, line);
            self.emit(Instruction::from_raw(c), line);
        }
        self.fs_mut().free_reg = (base + 1) as u8;
    }
    pub(crate) fn enter_function(&mut self, source: &str) {
        let fs = FuncState::new(source);
        self.func_states.push(fs);
    }
    #[allow(clippy::expect_used)]
    pub(crate) fn leave_function(&mut self) -> Proto {
        self.emit_abc(OpCode::Return, 0, 1, 0, self.current_line);
        self.remove_locals(0);
        let mut fs = self
            .func_states
            .pop()
            .expect("cannot leave global function");
        fs.proto.upvalue_names = fs.upvalues.iter().map(|uv| uv.name.clone()).collect();
        fs.proto
    }
    #[allow(clippy::expect_used)]
    fn finish_main(&mut self) -> Proto {
        self.emit_abc(OpCode::Return, 0, 1, 0, self.current_line);
        self.remove_locals(0);
        let mut fs = self
            .func_states
            .pop()
            .expect("cannot finish without main function");
        fs.proto.upvalue_names = fs.upvalues.iter().map(|uv| uv.name.clone()).collect();
        fs.proto
    }
}
pub fn compile(source: &[u8], name: &str) -> LuaResult<ProtoRef> {
    let block = parser::parse(source, name)?;
    let mut compiler = Compiler::new(name);
    compiler.fs_mut().proto.is_vararg = 2; 
    compiler.fs_mut().proto.num_params = 0;
    compile_block(&mut compiler, &block)?;
    let proto = compiler.finish_main();
    Ok(ProtoRef::new(proto))
}
pub fn compile_with_lexer(lexer: Lexer<'_>, name: &str) -> LuaResult<ProtoRef> {
    let block = parser::parse_with_lexer(lexer)?;
    let mut compiler = Compiler::new(name);
    compiler.fs_mut().proto.is_vararg = 2; 
    compiler.fs_mut().proto.num_params = 0;
    compile_block(&mut compiler, &block)?;
    let proto = compiler.finish_main();
    Ok(ProtoRef::new(proto))
}

mod statements;
mod expressions;
use statements::*;
use expressions::*;

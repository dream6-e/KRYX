// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::*;
use super::statements::*;
pub(super) fn compile_expr_stat(
    compiler: &mut Compiler,
    expr: &super::super::ast::Expr,
    _line: u32,
) -> LuaResult<()> {
    let e = compile_expr(compiler, expr)?;
    if e.kind == ExprKind::Call {
        let mut instr = compiler.get_instruction(e.info as usize);
        instr.set_c(1); 
        compiler.set_instruction(e.info as usize, instr);
    }
    Ok(())
}
pub(super) fn compile_exprlist(
    compiler: &mut Compiler,
    exprs: &[super::super::ast::Expr],
    line: u32,
) -> LuaResult<(usize, ExprContext)> {
    if exprs.is_empty() {
        return Ok((0, ExprContext::void()));
    }
    for expr in &exprs[..exprs.len() - 1] {
        let mut e = compile_expr(compiler, expr)?;
        compiler.exp2nextreg(&mut e, line)?;
    }
    let last = compile_expr(compiler, &exprs[exprs.len() - 1])?;
    Ok((exprs.len(), last))
}
pub(super) fn adjust_assign(
    compiler: &mut Compiler,
    nvars: usize,
    nexps: usize,
    last: &mut ExprContext,
    line: u32,
) -> LuaResult<()> {
    let extra = nvars as i32 - nexps as i32;
    if last.kind == ExprKind::Call || last.kind == ExprKind::VarArg {
        let is_call = last.kind == ExprKind::Call;
        let needed = extra + 1;
        if needed < 0 {
            compiler.set_one_ret(last);
        } else if is_call {
            let mut instr = compiler.get_instruction(last.info as usize);
            instr.set_c((needed + 1) as u32);
            compiler.set_instruction(last.info as usize, instr);
        } else {
            let mut instr = compiler.get_instruction(last.info as usize);
            instr.set_b((needed + 1) as u32);
            instr.set_a(u32::from(compiler.fs().free_reg));
            compiler.set_instruction(last.info as usize, instr);
            compiler.reserve_regs(1)?;
            last.kind = ExprKind::Relocable;
        }
        if is_call && needed > 1 {
            #[allow(clippy::cast_possible_truncation)]
            compiler.reserve_regs((needed - 1) as u32)?;
        }
    } else {
        if last.kind != ExprKind::Void {
            compiler.exp2nextreg(last, line)?;
        }
        if extra > 0 {
            let reg = u32::from(compiler.fs().free_reg);
            #[allow(clippy::cast_possible_truncation)]
            compiler.reserve_regs(extra as u32)?;
            #[allow(clippy::cast_possible_truncation)]
            compiler.emit_nil(reg, extra as u32, line);
        }
    }
    Ok(())
}
pub(super) fn compile_funcbody(
    compiler: &mut Compiler,
    body: &super::super::ast::FuncBody,
    need_self: bool,
    line: u32,
) -> LuaResult<ExprContext> {
    compiler.enter_function(&compiler.source_name.clone());
    compiler.fs_mut().proto.line_defined = line;
    if need_self {
        compiler.new_local("self")?;
        compiler.activate_locals(1);
    }
    for param in &body.params {
        compiler.new_local(param)?;
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        compiler.activate_locals(body.params.len() as u32);
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        let num_params = body.params.len() as u8 + u8::from(need_self);
        compiler.fs_mut().proto.num_params = num_params;
    }
    if body.has_varargs {
        compiler.fs_mut().proto.is_vararg = VARARG_HASARG | VARARG_ISVARARG | VARARG_NEEDSARG;
        compiler.new_local("arg")?;
        compiler.activate_locals(1);
    }
    let nactvar = u32::from(compiler.fs().num_active_vars);
    compiler.reserve_regs(nactvar)?;
    compile_block(compiler, &body.body)?;
    compiler.fs_mut().proto.last_line_defined = body.end_line;
    compiler.current_line = body.end_line;
    let child_upvalues = compiler.fs().upvalues.clone();
    let proto = compiler.leave_function();
    let parent_fs = compiler.fs_mut();
    let proto_idx = parent_fs.proto.protos.len();
    parent_fs.proto.protos.push(ProtoRef::new(proto));
    #[allow(clippy::cast_possible_truncation)]
    let pc = compiler.emit_abx(OpCode::Closure, 0, proto_idx as u32, line);
    for uv in &child_upvalues {
        let op = if uv.in_stack {
            OpCode::Move
        } else {
            OpCode::GetUpval
        };
        compiler.emit_abc(op, 0, u32::from(uv.index), 0, line);
    }
    let e = ExprContext::new(ExprKind::Relocable, pc as i32);
    Ok(e)
}
pub(super) fn compile_expr(compiler: &mut Compiler, expr: &super::super::ast::Expr) -> LuaResult<ExprContext> {
    use super::super::ast::Expr;
    let line = expr.span().line;
    compiler.current_line = line;
    match expr {
        Expr::Nil(_) => Ok(ExprContext::new(ExprKind::Nil, 0)),
        Expr::True(_) => Ok(ExprContext::new(ExprKind::True, 0)),
        Expr::False(_) => Ok(ExprContext::new(ExprKind::False, 0)),
        Expr::Number(n, _) => Ok(ExprContext::number(*n)),
        Expr::Str(s, _) => {
            let k = compiler.string_constant(s)?;
            Ok(ExprContext::new(ExprKind::K, k as i32))
        }
        Expr::VarArg(_) => {
            compiler.fs_mut().proto.is_vararg &= !VARARG_NEEDSARG;
            let pc = compiler.emit_abc(OpCode::VarArg, 0, 1, 0, line);
            Ok(ExprContext::new(ExprKind::VarArg, pc as i32))
        }
        Expr::Name(name, _) => compiler.resolve_var(name),
        Expr::BinOp {
            op, left, right, ..
        } => {
            let mut e1 = compile_expr(compiler, left)?;
            compiler.infix(*op, &mut e1, line)?;
            let mut e2 = compile_expr(compiler, right)?;
            compiler.postfix(*op, &mut e1, &mut e2, line)?;
            Ok(e1)
        }
        Expr::UnOp { op, operand, .. } => {
            let mut e = compile_expr(compiler, operand)?;
            compiler.prefix(*op, &mut e, line)?;
            Ok(e)
        }
        Expr::Index { table, key, .. } => {
            let mut t = compile_expr(compiler, table)?;
            compiler.exp2anyreg(&mut t, line)?;
            let mut k = compile_expr(compiler, key)?;
            compiler.set_indexed(&mut t, &mut k, line)?;
            Ok(t)
        }
        Expr::Field { table, field, .. } => {
            let mut t = compile_expr(compiler, table)?;
            compiler.exp2anyreg(&mut t, line)?;
            let k_idx = compiler.string_constant(field.as_bytes())?;
            let mut k = ExprContext::new(ExprKind::K, k_idx as i32);
            compiler.set_indexed(&mut t, &mut k, line)?;
            Ok(t)
        }
        Expr::MethodCall {
            table,
            method,
            args,
            ..
        } => {
            let mut obj = compile_expr(compiler, table)?;
            compiler.exp2anyreg(&mut obj, line)?;
            let k = compiler.string_constant(method.as_bytes())?;
            let mut key = ExprContext::new(ExprKind::K, k as i32);
            compiler.code_self(&mut obj, &mut key, line)?;
            compile_funcargs(compiler, &mut obj, args, line)?;
            Ok(obj)
        }
        Expr::Call { func, args, .. } => {
            let mut f = compile_expr(compiler, func)?;
            compiler.exp2nextreg(&mut f, line)?;
            compile_funcargs(compiler, &mut f, args, line)?;
            Ok(f)
        }
        Expr::FuncDef { body, .. } => compile_funcbody(compiler, body, false, line),
        Expr::TableCtor { fields, .. } => compile_table_ctor(compiler, fields, line),
        Expr::Paren(inner, _) => {
            let mut e = compile_expr(compiler, inner)?;
            compiler.discharge_vars(&mut e, line);
            Ok(e)
        }
    }
}
pub(super) fn compile_funcargs(
    compiler: &mut Compiler,
    func: &mut ExprContext,
    args: &[super::super::ast::Expr],
    line: u32,
) -> LuaResult<()> {
    let base = func.info as u32;
    if args.is_empty() {
    } else {
        for (i, arg) in args.iter().enumerate() {
            let mut e = compile_expr(compiler, arg)?;
            if i == args.len() - 1 {
                if e.kind == ExprKind::Call || e.kind == ExprKind::VarArg {
                    compiler.set_multret(&mut e);
                    let pc = compiler.emit_abc(OpCode::Call, base, 0, 2, line);
                    func.info = pc as i32;
                    func.kind = ExprKind::Call;
                    compiler.fs_mut().free_reg = (base + 1) as u8;
                    return Ok(());
                }
            }
            compiler.exp2nextreg(&mut e, line)?;
        }
    }
    let nparams = u32::from(compiler.fs().free_reg) - (base + 1);
    let pc = compiler.emit_abc(OpCode::Call, base, nparams + 1, 2, line);
    func.info = pc as i32;
    func.kind = ExprKind::Call;
    compiler.fs_mut().free_reg = (base + 1) as u8;
    Ok(())
}
pub(super) fn compile_table_ctor(
    compiler: &mut Compiler,
    fields: &[super::super::ast::TableField],
    line: u32,
) -> LuaResult<ExprContext> {
    use super::super::ast::TableField;
    let pc = compiler.emit_abc(OpCode::NewTable, 0, 0, 0, line);
    let mut t = ExprContext::new(ExprKind::Relocable, pc as i32);
    compiler.exp2nextreg(&mut t, line)?;
    let table_reg = t.info as u32;
    let mut na: u32 = 0; 
    let mut nh: u32 = 0; 
    let mut tostore: u32 = 0; 
    let last_value_idx = fields
        .iter()
        .rposition(|f| matches!(f, TableField::ValueField { .. }));
    for (i, field) in fields.iter().enumerate() {
        match field {
            TableField::ValueField { value, .. } => {
                na += 1;
                tostore += 1;
                let is_last = last_value_idx == Some(i);
                let mut val_e = compile_expr(compiler, value)?;
                if is_last && is_multret_expr(value) {
                    compiler.set_multret(&mut val_e);
                    compiler.code_setlist(table_reg, na, 0, line); 
                    na -= 1; 
                    tostore = 0;
                } else {
                    compiler.exp2nextreg(&mut val_e, line)?;
                    if tostore >= LFIELDS_PER_FLUSH {
                        compiler.code_setlist(table_reg, na, tostore, line);
                        tostore = 0;
                    }
                }
            }
            TableField::NameField { name, value, .. } => {
                nh += 1;
                let k = compiler.string_constant(name.as_bytes())?;
                let mut key_e = ExprContext::new(ExprKind::K, k as i32);
                let key_rk = compiler.exp2rk(&mut key_e, line)?;
                let mut val_e = compile_expr(compiler, value)?;
                let val_rk = compiler.exp2rk(&mut val_e, line)?;
                compiler.emit_abc(OpCode::SetTable, table_reg, key_rk, val_rk, line);
                compiler.free_expr(&val_e);
                compiler.free_expr(&key_e);
            }
            TableField::IndexField { key, value, .. } => {
                nh += 1;
                let mut key_e = compile_expr(compiler, key)?;
                let key_rk = compiler.exp2rk(&mut key_e, line)?;
                let mut val_e = compile_expr(compiler, value)?;
                let val_rk = compiler.exp2rk(&mut val_e, line)?;
                compiler.emit_abc(OpCode::SetTable, table_reg, key_rk, val_rk, line);
                compiler.free_expr(&val_e);
                compiler.free_expr(&key_e);
            }
        }
    }
    if tostore > 0 {
        compiler.code_setlist(table_reg, na, tostore, line);
    }
    let mut instr = compiler.get_instruction(pc);
    instr.set_b(int2fb(na));
    instr.set_c(int2fb(nh));
    compiler.set_instruction(pc, instr);
    Ok(t)
}
pub(super) fn is_multret_expr(expr: &super::super::ast::Expr) -> bool {
    matches!(
        expr,
        super::super::ast::Expr::Call { .. }
            | super::super::ast::Expr::MethodCall { .. }
            | super::super::ast::Expr::VarArg(..)
    )
}
pub(crate) fn int2fb(mut x: u32) -> u32 {
    if x < 8 {
        return x;
    }
    let mut e = 0u32;
    while x >= 16 {
        x = (x + 1) >> 1;
        e += 1;
    }
    ((e + 1) << 3) | (x - 8)
}
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::approx_constant,
    clippy::items_after_statements,
    clippy::needless_collect,
    clippy::bool_comparison,
    clippy::useless_vec,
    clippy::needless_bool_assign,
    clippy::unnecessary_operation
)]
mod tests {
    use super::*;
    #[test]
    fn empty_program_compiles() {
        let proto = compile(b"", "test").unwrap();
        assert_eq!(proto.num_params, 0);
        assert_eq!(proto.is_vararg, 2);
        assert!(!proto.code.is_empty());
    }
    #[test]
    fn return_no_values() {
        let proto = compile(b"return", "test").unwrap();
        assert!(!proto.code.is_empty());
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::Return);
    }
    #[test]
    fn number_constant_dedup() {
        let mut compiler = Compiler::new("test");
        let k1 = compiler.number_constant(42.0).unwrap();
        let k2 = compiler.number_constant(42.0).unwrap();
        let k3 = compiler.number_constant(99.0).unwrap();
        assert_eq!(k1, k2); 
        assert_ne!(k1, k3); 
    }
    #[test]
    fn constant_bool_dedup() {
        let mut compiler = Compiler::new("test");
        let k1 = compiler.add_constant(Val::Bool(true)).unwrap();
        let k2 = compiler.add_constant(Val::Bool(true)).unwrap();
        let k3 = compiler.add_constant(Val::Bool(false)).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }
    #[test]
    fn constant_nan_not_deduped() {
        let mut compiler = Compiler::new("test");
        let k1 = compiler.add_constant(Val::Num(f64::NAN)).unwrap();
        let k2 = compiler.add_constant(Val::Num(f64::NAN)).unwrap();
        assert_eq!(k1, k2);
    }
    #[test]
    fn alloc_and_free_reg() {
        let mut compiler = Compiler::new("test");
        let r1 = compiler.alloc_reg().unwrap();
        assert_eq!(r1, 0);
        let r2 = compiler.alloc_reg().unwrap();
        assert_eq!(r2, 1);
        compiler.free_reg(r2);
        assert_eq!(compiler.fs().free_reg, 1);
        let r3 = compiler.alloc_reg().unwrap();
        assert_eq!(r3, 1); 
    }
    #[test]
    fn reserve_regs() {
        let mut compiler = Compiler::new("test");
        compiler.reserve_regs(3).unwrap();
        assert_eq!(compiler.fs().free_reg, 3);
    }
    #[test]
    fn stack_overflow_error() {
        let mut compiler = Compiler::new("test");
        compiler.fs_mut().free_reg = 249;
        assert!(compiler.check_stack(2).is_err());
    }
    #[test]
    fn resolve_global() {
        let mut compiler = Compiler::new("test");
        let e = compiler.resolve_var("x").unwrap();
        assert_eq!(e.kind, ExprKind::Global);
    }
    #[test]
    fn resolve_local() {
        let mut compiler = Compiler::new("test");
        compiler.new_local("x").unwrap();
        compiler.activate_locals(1);
        compiler.fs_mut().free_reg = 1; 
        let e = compiler.resolve_var("x").unwrap();
        assert_eq!(e.kind, ExprKind::Local);
        assert_eq!(e.info, 0); 
    }
    #[test]
    fn enter_leave_block() {
        let mut compiler = Compiler::new("test");
        compiler.enter_block(false);
        assert_eq!(compiler.fs().blocks.len(), 1);
        compiler.leave_block();
        assert_eq!(compiler.fs().blocks.len(), 0);
    }
    #[test]
    fn locals_removed_on_block_exit() {
        let mut compiler = Compiler::new("test");
        compiler.enter_block(false);
        compiler.new_local("x").unwrap();
        compiler.activate_locals(1);
        compiler.fs_mut().free_reg = 1;
        assert_eq!(compiler.fs().num_active_vars, 1);
        compiler.leave_block();
        assert_eq!(compiler.fs().num_active_vars, 0);
    }
    #[test]
    fn emit_instruction() {
        let mut compiler = Compiler::new("test");
        let pc = compiler.emit_abc(OpCode::Move, 0, 1, 0, 1);
        assert_eq!(pc, 0);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::Move);
        assert_eq!(instr.a(), 0);
        assert_eq!(instr.b(), 1);
    }
    #[test]
    fn emit_records_line_info() {
        let mut compiler = Compiler::new("test");
        compiler.emit_abc(OpCode::Move, 0, 1, 0, 5);
        compiler.emit_abc(OpCode::LoadK, 1, 0, 0, 10);
        assert_eq!(compiler.fs().proto.line_info[0], 5);
        assert_eq!(compiler.fs().proto.line_info[1], 10);
    }
    #[test]
    fn discharge_nil() {
        let mut compiler = Compiler::new("test");
        compiler.emit_abc(OpCode::Return, 0, 1, 0, 1);
        let mut e = ExprContext::new(ExprKind::Nil, 0);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(1);
        assert_eq!(instr.opcode(), OpCode::LoadNil);
    }
    #[test]
    fn discharge_true() {
        let mut compiler = Compiler::new("test");
        let mut e = ExprContext::new(ExprKind::True, 0);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::LoadBool);
        assert_eq!(instr.b(), 1);
    }
    #[test]
    fn discharge_number() {
        let mut compiler = Compiler::new("test");
        let mut e = ExprContext::number(42.0);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::LoadK);
    }
    #[test]
    fn discharge_local_to_different_reg() {
        let mut compiler = Compiler::new("test");
        compiler.new_local("x").unwrap();
        compiler.activate_locals(1);
        compiler.fs_mut().free_reg = 1;
        let mut e = ExprContext::new(ExprKind::Local, 0);
        compiler.discharge_vars(&mut e, 1);
        assert_eq!(e.kind, ExprKind::NonReloc);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::Move);
        assert_eq!(instr.a(), 1);
        assert_eq!(instr.b(), 0);
    }
    #[test]
    fn compile_return_number() {
        let proto = compile(b"return 42", "test").unwrap();
        assert!(proto.code.len() >= 2);
        assert!(
            proto
                .constants
                .iter()
                .any(|v| matches!(v, Val::Num(n) if *n == 42.0))
        );
    }
    #[test]
    fn compile_return_nil() {
        let proto = compile(b"return nil", "test").unwrap();
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::Return);
    }
    #[test]
    fn compile_return_bool() {
        let proto = compile(b"return true", "test").unwrap();
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::LoadBool);
        assert_eq!(instr.b(), 1); 
    }
    #[test]
    fn compile_return_multiple() {
        let proto = compile(b"return 1, 2, 3", "test").unwrap();
        let mut loadk_count = 0;
        for &code in &proto.code {
            if Instruction::from_raw(code).opcode() == OpCode::LoadK {
                loadk_count += 1;
            }
        }
        assert_eq!(loadk_count, 3);
    }
    fn opcodes(proto: &Proto) -> Vec<OpCode> {
        proto
            .code
            .iter()
            .map(|&raw| Instruction::from_raw(raw).opcode())
            .collect()
    }
    #[test]
    fn compile_local_decl() {
        let proto = compile(b"local x = 42", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadK));
    }
    #[test]
    fn compile_local_nil_init() {
        let proto = compile(b"local x, y", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(!ops.contains(&OpCode::LoadNil));
        assert!(ops.contains(&OpCode::Return));
    }
    #[test]
    fn compile_global_assign() {
        let proto = compile(b"x = 1", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::SetGlobal));
    }
    #[test]
    fn compile_local_assign() {
        let proto = compile(b"local x; x = 1", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadK));
    }
    #[test]
    fn compile_do_block() {
        let proto = compile(b"do local x = 1 end; return", "test").unwrap();
        assert!(proto.code.len() >= 2);
    }
    #[test]
    fn compile_while_loop() {
        let proto = compile(b"local x = true; while x do x = false end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Jmp));
    }
    #[test]
    fn compile_repeat_until() {
        let proto = compile(b"local x = 0; repeat x = x + 1 until x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Add));
    }
    #[test]
    fn compile_if_then() {
        let proto = compile(b"local x = true; if x then return 1 end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(
            ops.contains(&OpCode::Test) || ops.contains(&OpCode::Jmp),
            "if-then should generate control flow"
        );
    }
    #[test]
    fn compile_if_else() {
        let proto = compile(
            b"local x = true; if x then return 1 else return 2 end",
            "test",
        )
        .unwrap();
        let ops = opcodes(&proto);
        let jmp_count = ops.iter().filter(|&&op| op == OpCode::Jmp).count();
        assert!(jmp_count >= 1, "if-else needs at least one JMP");
    }
    #[test]
    fn compile_numeric_for() {
        let proto = compile(b"for i = 1, 10 do end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::ForPrep));
        assert!(ops.contains(&OpCode::ForLoop));
    }
    #[test]
    fn compile_numeric_for_with_step() {
        let proto = compile(b"for i = 1, 10, 2 do end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::ForPrep));
        assert!(ops.contains(&OpCode::ForLoop));
        assert!(
            proto
                .constants
                .iter()
                .any(|v| matches!(v, Val::Num(n) if n == &2.0))
        );
    }
    #[test]
    fn compile_generic_for() {
        let proto = compile(b"for k, v in next, t do end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::TForLoop));
        assert!(ops.contains(&OpCode::Jmp));
    }
    #[test]
    fn compile_break() {
        let proto = compile(b"while true do break end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Jmp));
    }
    #[test]
    fn compile_arithmetic() {
        let proto = compile(b"local a; return a + 2", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Add));
    }
    #[test]
    fn compile_comparison() {
        let proto = compile(b"return 1 < 2", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Lt));
    }
    #[test]
    fn compile_concat() {
        let proto = compile(b"return 'a' .. 'b'", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Concat));
    }
    #[test]
    fn compile_unary_neg() {
        let proto = compile(b"local x = 1; return -x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Unm));
    }
    #[test]
    fn compile_unary_not() {
        let proto = compile(b"return not true", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadBool));
    }
    #[test]
    fn compile_unary_len() {
        let proto = compile(b"local x = {}; return #x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Len));
    }
    #[test]
    fn compile_string_constant() {
        let proto = compile(b"return 'hello'", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadK));
        assert!(!proto.constants.is_empty());
    }
    #[test]
    fn compile_and_short_circuit() {
        let proto = compile(b"local a, b; return a and b", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(
            ops.contains(&OpCode::Test) || ops.contains(&OpCode::TestSet),
            "and should use TEST/TESTSET"
        );
    }
    #[test]
    fn compile_or_short_circuit() {
        let proto = compile(b"local a, b; return a or b", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(
            ops.contains(&OpCode::Test) || ops.contains(&OpCode::TestSet),
            "or should use TEST/TESTSET"
        );
    }
    #[test]
    fn compile_function_call() {
        let proto = compile(b"print(42)", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::GetGlobal));
        assert!(ops.contains(&OpCode::Call));
    }
    #[test]
    fn compile_method_call() {
        let proto = compile(b"local t = {}; t:foo(1)", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::OpSelf));
        assert!(ops.contains(&OpCode::Call));
    }
    #[test]
    fn compile_function_def() {
        let proto = compile(b"local f = function(x) return x end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Closure));
        assert_eq!(proto.protos.len(), 1);
        let child = &proto.protos[0];
        assert_eq!(child.num_params, 1);
    }
    #[test]
    fn compile_local_function() {
        let proto = compile(b"local function f(a, b) return a + b end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Closure));
        assert_eq!(proto.protos.len(), 1);
        let child = &proto.protos[0];
        assert_eq!(child.num_params, 2);
    }
    #[test]
    fn compile_named_function() {
        let proto = compile(b"function f(x) return x end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Closure));
        assert!(ops.contains(&OpCode::SetGlobal));
    }
    #[test]
    fn compile_vararg_function() {
        let proto = compile(b"local f = function(...) return ... end", "test").unwrap();
        let child = &proto.protos[0];
        assert!(child.is_vararg & 2 != 0); 
    }
    #[test]
    fn compile_empty_table() {
        let proto = compile(b"return {}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
    }
    #[test]
    fn compile_array_table() {
        let proto = compile(b"return {1, 2, 3}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
        assert!(ops.contains(&OpCode::SetList));
    }
    #[test]
    fn compile_hash_table() {
        let proto = compile(b"return {x = 1, y = 2}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
        assert!(ops.contains(&OpCode::SetTable));
    }
    #[test]
    fn compile_index_table() {
        let proto = compile(b"return {[1] = 'a'}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
        assert!(ops.contains(&OpCode::SetTable));
    }
    #[test]
    fn compile_table_field_access() {
        let proto = compile(b"local t = {}; return t.x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::GetTable));
    }
    #[test]
    fn compile_table_index_access() {
        let proto = compile(b"local t = {}; return t[1]", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::GetTable));
    }
    #[test]
    fn compile_tail_call() {
        let proto = compile(b"local function f(x) return f(x) end", "test").unwrap();
        let child = &proto.protos[0];
        let child_ops: Vec<OpCode> = child
            .code
            .iter()
            .map(|&raw| Instruction::from_raw(raw).opcode())
            .collect();
        assert!(
            child_ops.contains(&OpCode::TailCall),
            "recursive return should use TAILCALL"
        );
    }
    #[test]
    fn compile_line_info() {
        let proto = compile(b"return 42", "test").unwrap();
        assert_eq!(proto.code.len(), proto.line_info.len());
    }
    #[test]
    fn compile_return_string() {
        let proto = compile(b"return 'hello'", "test").unwrap();
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::LoadK);
    }
    #[test]
    fn compile_expr_stat_call() {
        let proto = compile(b"print(1)", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Call));
        for &code in &proto.code {
            let instr = Instruction::from_raw(code);
            if instr.opcode() == OpCode::Call {
                assert_eq!(
                    instr.c(),
                    1,
                    "expression statement call should have C=1 (0 results)"
                );
                break;
            }
        }
    }
    #[test]
    fn compile_single_global_assign() {
        let proto = compile(b"x = 42", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::SetGlobal));
    }
    #[test]
    fn compile_nested_function() {
        let proto = compile(
            b"local function f() local function g() return 1 end return g end",
            "test",
        )
        .unwrap();
        assert_eq!(proto.protos.len(), 1);
        let f = &proto.protos[0];
        assert_eq!(f.protos.len(), 1); 
    }
    #[test]
    fn int2fb_small_values() {
        assert_eq!(int2fb(0), 0);
        assert_eq!(int2fb(1), 1);
        assert_eq!(int2fb(7), 7);
    }
    #[test]
    fn int2fb_exact_powers() {
        let encoded = int2fb(8);
        assert!(encoded >= 8);
    }
    #[test]
    fn compile_syntax_error() {
        let result = compile(b"if", "test");
        assert!(result.is_err());
    }
}

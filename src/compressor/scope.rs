// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::collections::HashMap;
use super::ast::{Block, LastStmt, Stmt, Expr, PrefixExpr, Var, Call, LocalVar, VarId};

pub struct ScopeResolver {
    scopes: Vec<HashMap<String, VarId>>,
    next_id: usize,
    pub var_usage: HashMap<VarId, usize>,
    /// VarId -> (def_pos, last_use_pos)，供活跃区间染色（不同作用域复用变量名）
    pub intervals: HashMap<VarId, (usize, usize)>,
    /// 每个函数的参数 VarId 列表（按声明顺序），供随机参数覆盖使用
    pub param_lists: Vec<Vec<VarId>>,
    /// VarId -> 原始变量名（用于 keep-list 直通：`_`/a/b/c/d 不重命名）
    pub decl_name: HashMap<VarId, String>,
    pos: usize,
}

impl ScopeResolver {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            next_id: 1,
            var_usage: HashMap::new(),
            intervals: HashMap::new(),
            param_lists: Vec::new(),
            decl_name: HashMap::new(),
            pos: 0,
        }
    }

    pub fn enter_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn exit_scope(&mut self) {
        self.scopes.pop();
    }

    #[inline]
    fn tick(&mut self) -> usize {
        self.pos += 1;
        self.pos
    }

    pub fn declare_local(&mut self, name: &str) -> VarId {
        let id = VarId(self.next_id);
        self.next_id += 1;

        let def = self.tick();
        self.intervals.insert(id, (def, def));
        self.var_usage.insert(id, 0);
        self.decl_name.insert(id, name.to_string());

        if let Some(current) = self.scopes.last_mut() {
            current.insert(name.to_string(), id);
        }
        id
    }

    /// 记录一组参数（函数声明/函数表达式），供 rename 阶段做随机参数覆盖
    pub fn note_param_list(&mut self, params: &[LocalVar]) {
        self.param_lists.push(params.iter().map(|p| p.id).collect());
    }

    pub fn resolve_var(&self, name: &str) -> Option<VarId> {
        for scope in self.scopes.iter().rev() {
            if let Some(&id) = scope.get(name) {
                return Some(id);
            }
        }
        None
    }

    pub fn record_usage(&mut self, id: VarId) {
        let use_pos = self.tick();
        if let Some(interval) = self.intervals.get_mut(&id) {
            if use_pos > interval.1 {
                interval.1 = use_pos;
            }
        }
        if let Some(count) = self.var_usage.get_mut(&id) {
            *count += 1;
        }
    }

    pub fn max_id(&self) -> usize {
        self.next_id - 1
    }
}

impl Block {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        r.enter_scope();
        for s in &mut self.stmts {
            s.resolve(r);
        }
        if let Some(l) = &mut self.last_stmt {
            l.resolve(r);
        }
        r.exit_scope();
    }

    pub fn resolve_no_scope_bracket(&mut self, r: &mut ScopeResolver) {
        for s in &mut self.stmts {
            s.resolve(r);
        }
        if let Some(l) = &mut self.last_stmt {
            l.resolve(r);
        }
    }
}

impl LastStmt {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            LastStmt::Return(exprs) => {
                for e in exprs {
                    e.resolve(r);
                }
            }
            LastStmt::Break | LastStmt::Continue => {}
        }
    }
}

impl Stmt {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Stmt::Assign(vars, exprs) => {
                for v in vars {
                    v.resolve(r);
                }
                for e in exprs {
                    e.resolve(r);
                }
            }
            Stmt::CompoundAssign(var, _op, rhs) => {
                var.resolve(r);
                rhs.resolve(r);
            }
            Stmt::Call(call) => {
                call.resolve(r);
            }
            Stmt::Do(block) => {
                block.resolve(r);
            }
            Stmt::While(cond, block) => {
                cond.resolve(r);
                block.resolve(r);
            }
            Stmt::Repeat(block, cond) => {
                r.enter_scope();
                block.resolve_no_scope_bracket(r);
                cond.resolve(r);
                r.exit_scope();
            }
            Stmt::If { cond, then_block, else_ifs, else_block } => {
                cond.resolve(r);
                then_block.resolve(r);
                for (c, b) in else_ifs {
                    c.resolve(r);
                    b.resolve(r);
                }
                if let Some(b) = else_block {
                    b.resolve(r);
                }
            }
            Stmt::For { var, init, limit, step, block } => {
                init.resolve(r);
                limit.resolve(r);
                if let Some(s) = step {
                    s.resolve(r);
                }
                r.enter_scope();
                var.id = r.declare_local(&var.name);
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::ForIn { vars, exprs, block } => {
                for e in exprs {
                    e.resolve(r);
                }
                r.enter_scope();
                for v in vars {
                    v.id = r.declare_local(&v.name);
                }
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::Function { path: _, method: _, params, is_vararg: _, block } => {
                r.enter_scope();
                for p in params.iter_mut() {
                    p.id = r.declare_local(&p.name);
                }
                r.note_param_list(params);
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::LocalFunction { var, params, is_vararg: _, block } => {
                var.id = r.declare_local(&var.name);
                r.enter_scope();
                for p in params.iter_mut() {
                    p.id = r.declare_local(&p.name);
                }
                r.note_param_list(params);
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::LocalAssign(vars, exprs) => {
                for e in exprs {
                    e.resolve(r);
                }
                for v in vars {
                    v.id = r.declare_local(&v.name);
                }
            }
        }
    }
}

impl Expr {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Expr::Nil | Expr::Boolean(_) | Expr::Number(_) | Expr::String(_) | Expr::Vararg => {}
            Expr::FuncDef(params, _, block) => {
                r.enter_scope();
                for p in params.iter_mut() {
                    p.id = r.declare_local(&p.name);
                }
                r.note_param_list(params);
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Expr::Table(fields) => {
                for f in fields {
                    match f {
                        super::ast::TableField::List(e) => e.resolve(r),
                        super::ast::TableField::Rec(k, v) => {
                            k.resolve(r);
                            v.resolve(r);
                        }
                    }
                }
            }
            Expr::BinOp(_, lhs, rhs) => {
                lhs.resolve(r);
                rhs.resolve(r);
            }
            Expr::UnOp(_, e) => {
                e.resolve(r);
            }
            Expr::Prefix(p) => {
                p.resolve(r);
            }
        }
    }
}

impl PrefixExpr {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            PrefixExpr::Var(v) => v.resolve(r),
            PrefixExpr::Call(c) => c.resolve(r),
            PrefixExpr::Paren(e) => e.resolve(r),
        }
    }
}

impl Var {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Var::Name(name, id) => {
                if let Some(resolved_id) = r.resolve_var(name) {
                    *id = resolved_id;
                    r.record_usage(resolved_id);
                }
            }
            Var::Index(prefix, expr) => {
                prefix.resolve(r);
                expr.resolve(r);
            }
            Var::Member(prefix, _) => {
                prefix.resolve(r);
            }
        }
    }
}

impl Call {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Call::Normal(prefix, args) => {
                prefix.resolve(r);
                for a in args {
                    a.resolve(r);
                }
            }
            Call::Method(prefix, _, args) => {
                prefix.resolve(r);
                for a in args {
                    a.resolve(r);
                }
            }
        }
    }
}
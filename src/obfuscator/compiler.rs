// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{ObfuscationError, Result};
use crate::ast::{Kind, Node, SyntaxTree};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(super) enum Constant {
    Nil,
    Bool(bool),
    Integer(u64),
    String(Vec<u8>),
}
#[repr(usize)]
#[derive(Clone, Copy, Debug)]
pub(super) enum Op {
    Load,
    Move,
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Neg,
    Not,
    Len,
    Return,
    GlobalPrint,
    Call,
}
pub(super) const OP_COUNT: usize = 22;
#[derive(Debug)]
pub(super) struct Instruction {
    pub op: Op,
    pub a: usize,
    pub b: usize,
    pub c: usize,
}
pub(super) struct Program {
    pub constants: Vec<Constant>,
    pub code: Vec<Instruction>,
    pub registers: usize,
}
struct Compiler<'a> {
    source: &'a [u8],
    constants: Vec<Constant>,
    code: Vec<Instruction>,
    locals: HashMap<Vec<u8>, usize>,
    next: usize,
}

pub(super) fn compile(tree: &SyntaxTree) -> Result<Program> {
    let mut c = Compiler {
        source: &tree.source,
        constants: vec![],
        code: vec![],
        locals: HashMap::new(),
        next: 1,
    };
    let mut returned = false;
    for statement in &tree.root.children {
        match statement.kind {
            Kind::Local | Kind::Const => c.local(statement)?,
            Kind::Return => {
                c.ret(statement)?;
                returned = true;
            }
            Kind::CallStatement => c.call(statement)?,
            _ => {
                return Err(c.error(
                    statement,
                    "当前 VM 仅支持顶层 local/const、print 调用和 return",
                ))
            }
        }
    }
    if !returned {
        c.emit(Op::Return, 1, 0, 0);
    }
    Ok(Program {
        constants: c.constants,
        code: c.code,
        registers: c.next.saturating_sub(1),
    })
}
impl Compiler<'_> {
    fn error(&self, node: &Node, message: &str) -> ObfuscationError {
        ObfuscationError(format!("字节偏移 {}：{}", node.span.start, message))
    }
    fn emit(&mut self, op: Op, a: usize, b: usize, c: usize) {
        self.code.push(Instruction { op, a, b, c });
    }
    fn allocate(&mut self) -> Result<usize> {
        if self.next > 50_000 {
            return Err(ObfuscationError("寄存器数量超过阶段一限制".into()));
        }
        let result = self.next;
        self.next += 1;
        Ok(result)
    }
    fn constant(&mut self, value: Constant) -> Result<usize> {
        self.constants.push(value);
        let dest = self.allocate()?;
        self.emit(Op::Load, dest, self.constants.len(), 0);
        Ok(dest)
    }
    fn local(&mut self, node: &Node) -> Result<()> {
        let bindings = &node.children[0].children;
        if bindings.iter().any(|b| b.children.len() != 1) {
            return Err(self.error(node, "暂不支持局部变量类型注解"));
        }
        let mut values = Vec::new();
        if let Some(list) = node.children.get(1) {
            for expr in &list.children {
                values.push(self.expr(expr)?);
            }
        }
        // All RHS values are evaluated before bindings become visible.
        for (index, binding) in bindings.iter().enumerate() {
            let src = if let Some(&r) = values.get(index) {
                r
            } else {
                self.constant(Constant::Nil)?
            };
            let dest = self.allocate()?;
            self.emit(Op::Move, dest, src, 0);
            let name = &binding.children[0];
            self.locals
                .insert(self.source[name.span.clone()].to_vec(), dest);
        }
        Ok(())
    }
    fn call(&mut self, statement: &Node) -> Result<()> {
        let node = &statement.children[0];
        if node.kind != Kind::Call
            || node.children[0].kind != Kind::Name
            || &self.source[node.children[0].span.clone()] != b"print"
            || self.locals.contains_key(b"print".as_slice())
        {
            return Err(self.error(statement, "阶段一仅支持未被局部变量遮蔽的全局 print 调用"));
        }
        let fun = self.allocate()?;
        self.emit(Op::GlobalPrint, fun, 0, 0);
        let mut values = Vec::new();
        for arg in &node.children[1..] {
            values.push(self.expr(arg)?);
        }
        let base = self.next;
        for src in values {
            let dest = self.allocate()?;
            self.emit(Op::Move, dest, src, 0);
        }
        self.emit(Op::Call, fun, base, node.children.len() - 1);
        Ok(())
    }
    fn ret(&mut self, node: &Node) -> Result<()> {
        let mut values = Vec::new();
        for expr in &node.children {
            values.push(self.expr(expr)?);
        }
        let base = self.next;
        for src in values {
            let dest = self.allocate()?;
            self.emit(Op::Move, dest, src, 0);
        }
        self.emit(Op::Return, base, node.children.len(), 0);
        Ok(())
    }
    fn expr(&mut self, root: &Node) -> Result<usize> {
        let mut tasks = vec![(root, false)];
        let mut values = Vec::new();
        while let Some((node, done)) = tasks.pop() {
            match &node.kind {
                Kind::Parenthesized if !done => tasks.push((&node.children[0], false)),
                Kind::Unary(_) | Kind::Binary(_) if !done => {
                    tasks.push((node, true));
                    for child in node.children.iter().rev() {
                        tasks.push((child, false));
                    }
                }
                Kind::Unary(op) if done => {
                    let op = match op.as_str() {
                        "-" => Op::Neg,
                        "not" => Op::Not,
                        "#" => Op::Len,
                        _ => return Err(self.error(node, "不支持的单目运算")),
                    };
                    let input = values.pop().unwrap();
                    let dest = self.allocate()?;
                    self.emit(op, dest, input, 0);
                    values.push(dest);
                }
                Kind::Binary(op) if done => {
                    let op = match op.as_str() {
                        "+" => Op::Add,
                        "-" => Op::Sub,
                        "*" => Op::Mul,
                        "/" => Op::Div,
                        "//" => Op::FloorDiv,
                        "%" => Op::Mod,
                        "^" => Op::Pow,
                        ".." => Op::Concat,
                        "==" => Op::Eq,
                        "~=" => Op::Ne,
                        "<" => Op::Lt,
                        "<=" => Op::Le,
                        ">" => Op::Gt,
                        ">=" => Op::Ge,
                        _ => return Err(self.error(node, "暂不支持短路逻辑等表达式")),
                    };
                    let right = values.pop().unwrap();
                    let left = values.pop().unwrap();
                    let dest = self.allocate()?;
                    self.emit(op, dest, left, right);
                    values.push(dest);
                }
                Kind::Nil => values.push(self.constant(Constant::Nil)?),
                Kind::Boolean => values.push(
                    self.constant(Constant::Bool(&self.source[node.span.clone()] == b"true"))?,
                ),
                Kind::Number => {
                    let raw = &self.source[node.span.clone()];
                    let text = String::from_utf8_lossy(raw).replace('_', "");
                    let (digits, radix) = if text.starts_with("0x") || text.starts_with("0X") {
                        (&text[2..], 16)
                    } else if text.starts_with("0b") || text.starts_with("0B") {
                        (&text[2..], 2)
                    } else {
                        (text.as_str(), 10)
                    };
                    let n = u64::from_str_radix(digits, radix)
                        .map_err(|_| self.error(node, "阶段一仅支持整数数字字面量"))?;
                    if n > 9_007_199_254_740_992 {
                        return Err(self.error(node, "整数超出精确表示范围"));
                    }
                    values.push(self.constant(Constant::Integer(n))?);
                }
                Kind::String => {
                    let raw = &self.source[node.span.clone()];
                    if raw.len() < 2
                        || !matches!(raw[0], b'\'' | b'"')
                        || raw[1..raw.len() - 1]
                            .iter()
                            .any(|c| matches!(c, b'\\' | b'\r' | b'\n'))
                    {
                        return Err(self.error(node, "阶段一仅支持无转义的短字符串"));
                    }
                    values.push(self.constant(Constant::String(raw[1..raw.len() - 1].to_vec()))?);
                }
                Kind::Name => {
                    let name = &self.source[node.span.clone()];
                    values.push(
                        *self
                            .locals
                            .get(name)
                            .ok_or_else(|| self.error(node, "不支持全局变量或未声明的名称"))?,
                    );
                }
                _ => return Err(self.error(node, "此表达式尚未由 VM 支持")),
            }
        }
        Ok(values.pop().unwrap())
    }
}

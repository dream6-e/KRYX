// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::ops::Range;

/// Syntax tree node. Spans are half-open byte offsets in `SyntaxTree::source`.
/// Node kinds include operator spelling, so consumers need not infer precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    pub span: Range<usize>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Block,
    Local,
    BindingList,
    TargetList,
    ValueList,
    Assignment,
    CompoundAssignment(String),
    CallStatement,
    Return,
    Break,
    Continue,
    Do,
    While,
    Repeat,
    If,
    Branch,
    ForNumeric,
    ForGeneric,
    FunctionStatement,
    LocalFunction,
    TypeAlias,
    TypeFunction,
    Export,
    Attributed,
    Attribute,
    TypeInstantiation,
    Const,
    ConditionalBinding,
    Name,
    Number,
    String,
    Boolean,
    Nil,
    Varargs,
    Parenthesized,
    Unary(String),
    Binary(String),
    Index,
    Field,
    Call,
    MethodCall,
    Function,
    Table,
    TableField,
    IfExpression,
    TypeAssertion,
    Interpolation,
    Parameter,
    Parameters,
    GenericParameters,
    Type,
    TypeBinary(String),
    TypeOptional,
    TypeField,
    TypeArguments,
}

/// The original bytes and every lexical token are retained, including trivia.
#[derive(Debug, Clone)]
pub struct SyntaxTree {
    pub source: Vec<u8>,
    pub tokens: Vec<crate::lexer::Token>,
    pub root: Node,
}

// Long left-associative expressions create deep trees without recursive parsing.
// Drop children iteratively to avoid overflowing the thread stack on those trees.
impl Drop for Node {
    fn drop(&mut self) {
        let mut pending = std::mem::take(&mut self.children);
        while let Some(mut node) = pending.pop() {
            pending.append(&mut node.children);
        }
    }
}

// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::ops::Range;

/// Syntax tree node. Spans are half-open byte offsets in `SyntaxTree::source`.
/// Node kinds include operator spelling, so consumers need not infer precedence.
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
    ConstFunction,
    TypeAlias,
    TypeFunction,
    ExportTypeAlias,
    ExportTypeFunction,
    Export,
    Attributed,
    Attribute,
    TypeInstantiation,
    Const,
    ConditionalBinding,
    ConditionalConstBinding,
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
    MethodField,
    Call,
    MethodCall,
    Function,
    Table,
    TableField,
    TableRecord,
    TableIndex,
    TableArray,
    IfExpression,
    TypeAssertion,
    Interpolation,
    Parameter,
    Parameters,
    GenericParameters,
    Type,
    TypeOf,
    TypeTuple,
    TypePack,
    TypeFunctionExpression,
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

// Tree depth can be proportional to input size, even when parsing is iterative.
impl Clone for Node {
    fn clone(&self) -> Self {
        enum Work<'a> {
            Visit(&'a Node),
            Build(&'a Node),
        }
        let mut work = vec![Work::Visit(self)];
        let mut done: Vec<Node> = Vec::new();
        while let Some(item) = work.pop() {
            match item {
                Work::Visit(node) => {
                    work.push(Work::Build(node));
                    for child in node.children.iter().rev() {
                        work.push(Work::Visit(child));
                    }
                }
                Work::Build(node) => {
                    let children = done.split_off(done.len() - node.children.len());
                    done.push(Node {
                        kind: node.kind.clone(),
                        span: node.span.clone(),
                        children,
                    });
                }
            }
        }
        done.pop().unwrap()
    }
}
impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some((a, b)) = pending.pop() {
            if a.kind != b.kind || a.span != b.span || a.children.len() != b.children.len() {
                return false;
            }
            pending.extend(a.children.iter().zip(b.children.iter()));
        }
        true
    }
}
impl Eq for Node {}
impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("kind", &self.kind)
            .field("span", &self.span)
            .field("child_count", &self.children.len())
            .finish()
    }
}

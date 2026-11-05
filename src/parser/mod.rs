// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
mod expr;
mod statements;
mod types;

use crate::ast::{Kind, Node, SyntaxTree};
use crate::lexer::{self, Token, TokenKind};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
    pub message: String,
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}
impl std::error::Error for ParseError {}

/// Parse without executing the input. All offsets are byte offsets.
pub fn parse(source: &[u8]) -> Result<SyntaxTree> {
    let tokens = lexer::lex(source).map_err(|e| error_at(source, e.offset, e.message))?;
    let significant = tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Whitespace | TokenKind::Comment))
        .cloned()
        .collect();
    let mut p = Parser {
        source,
        tokens: significant,
        pos: 0,
        depth: 0,
        loops: 0,
        vararg: true,
    };
    let root = p.block(&[])?;
    if !p.eof() {
        return Err(p.error("意外的块结束符"));
    }
    Ok(SyntaxTree {
        source: source.to_vec(),
        tokens,
        root,
    })
}

fn error_at(source: &[u8], offset: usize, message: String) -> ParseError {
    let offset = offset.min(source.len());
    let prefix = &source[..offset];
    let line = 1 + prefix.iter().filter(|&&c| c == b'\n').count();
    let column = 1 + prefix
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(prefix.len(), |p| prefix.len() - p - 1);
    ParseError {
        offset,
        line,
        column,
        message,
    }
}

struct Parser<'a> {
    source: &'a [u8],
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
    loops: usize,
    vararg: bool,
}
type Result<T> = std::result::Result<T, ParseError>;
impl Parser<'_> {
    fn token(&self) -> &Token {
        &self.tokens[self.pos]
    }
    fn text(&self) -> &[u8] {
        &self.source[self.token().span.clone()]
    }
    fn at(&self, s: &str) -> bool {
        self.text() == s.as_bytes()
    }
    fn at_next(&self, s: &str) -> bool {
        self.tokens
            .get(self.pos + 1)
            .is_some_and(|t| &self.source[t.span.clone()] == s.as_bytes())
    }
    fn eof(&self) -> bool {
        self.token().kind == TokenKind::Eof
    }
    fn offset(&self) -> usize {
        self.token().span.start
    }
    fn end(&self) -> usize {
        if self.pos == 0 {
            0
        } else {
            self.tokens[self.pos - 1].span.end
        }
    }
    fn node(&self, kind: Kind, start: usize, children: Vec<Node>) -> Node {
        Node {
            kind,
            span: start..self.end().max(start),
            children,
        }
    }
    fn error(&self, msg: impl Into<String>) -> ParseError {
        error_at(self.source, self.offset(), msg.into())
    }
    fn bump(&mut self) {
        if !self.eof() {
            self.pos += 1;
        }
    }
    fn eat(&mut self, s: &str) -> bool {
        if self.at(s) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: &str) -> Result<()> {
        if self.eat(s) {
            Ok(())
        } else {
            Err(self.error(format!("需要 `{s}`")))
        }
    }
    fn name(&mut self) -> Result<Node> {
        const KEYWORDS: &[&[u8]] = &[
            b"and",
            b"break",
            b"do",
            b"else",
            b"elseif",
            b"end",
            b"false",
            b"for",
            b"function",
            b"if",
            b"in",
            b"local",
            b"nil",
            b"not",
            b"or",
            b"repeat",
            b"return",
            b"then",
            b"true",
            b"until",
            b"while",
        ];
        if self.token().kind != TokenKind::Name || KEYWORDS.contains(&self.text()) {
            return Err(self.error("需要标识符"));
        }
        let start = self.offset();
        self.bump();
        Ok(self.node(Kind::Name, start, vec![]))
    }
    fn enter(&mut self) -> Result<()> {
        if self.depth >= 48 {
            Err(self.error("语法嵌套超过限制（48）"))
        } else {
            self.depth += 1;
            Ok(())
        }
    }
    fn list(&mut self) -> Result<Vec<Node>> {
        let mut v = vec![self.expression(0)?];
        while self.eat(",") {
            v.push(self.expression(0)?);
        }
        Ok(v)
    }
}

// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{Parser, Result};
use crate::ast::{Kind, Node};
use crate::lexer::TokenKind;

impl Parser<'_> {
    pub(super) fn generics(&mut self) -> Result<Node> {
        let start = self.offset();
        self.expect("<")?;
        let mut parts = vec![];
        loop {
            let at = self.offset();
            let mut inner = vec![self.name()?];
            self.eat("...");
            if self.eat("=") {
                inner.push(self.return_type()?);
            }
            parts.push(self.node(Kind::Parameter, at, inner));
            if !self.eat(",") {
                break;
            }
        }
        self.expect(">")?;
        Ok(self.node(Kind::GenericParameters, start, parts))
    }
    pub(super) fn return_type(&mut self) -> Result<Node> {
        self.parse_type(true)
    }
    pub(super) fn type_expression(&mut self) -> Result<Node> {
        self.parse_type(false)
    }
    fn parse_type(&mut self, allow_pack: bool) -> Result<Node> {
        self.enter()?;
        let r = self.type_binary(0, allow_pack);
        self.depth -= 1;
        r
    }
    fn type_binary(&mut self, _min: u8, allow_pack: bool) -> Result<Node> {
        let start = self.offset();
        let mut operator = if self.at("|") || self.at("&") {
            let op = String::from_utf8_lossy(self.text()).into_owned();
            self.bump();
            Some(op)
        } else {
            None
        };
        let mut lhs = self.type_atom(allow_pack)?;
        while self.at("|") || self.at("&") {
            let op = String::from_utf8_lossy(self.text()).into_owned();
            if operator.as_ref().is_some_and(|first| first != &op) {
                return Err(self.error("联合类型和交叉类型不能混用；请使用括号"));
            }
            operator = Some(op.clone());
            self.bump();
            let rhs = self.type_atom(false)?;
            lhs = self.node(Kind::TypeBinary(op), start, vec![lhs, rhs]);
        }
        Ok(lhs)
    }
    fn type_atom(&mut self, allow_pack: bool) -> Result<Node> {
        let start = self.offset();
        let mut parts = vec![];
        if self.at("...") {
            if !allow_pack {
                return Err(self.error("此处不允许类型包"));
            }
            self.bump();
            parts.push(self.type_expression()?);
        } else if self.at("<") {
            parts.push(self.generics()?);
            parts.push(self.type_atom(false)?);
        } else if self.eat("(") {
            let mut has_names = false;
            if !self.at(")") {
                loop {
                    let at = self.offset();
                    let mut p = vec![];
                    if self.token().kind == TokenKind::Name && self.at_next(":") {
                        has_names = true;
                        p.push(self.name()?);
                        self.expect(":")?;
                    }
                    p.push(self.type_expression()?);
                    parts.push(self.node(Kind::Parameter, at, p));
                    if !self.eat(",") {
                        break;
                    }
                }
            }
            self.expect(")")?;
            if self.eat("->") {
                parts.push(self.return_type()?);
            } else if !allow_pack && (parts.len() != 1 || has_names) {
                return Err(self.error("此处的类型列表需要 `->`"));
            }
        } else if self.eat("{") {
            while !self.at("}") {
                let at = self.offset();
                let mut f = vec![];
                if (self.at("read") || self.at("write")) && !self.at_next(":") {
                    f.push(self.name()?);
                }
                if self.eat("[") {
                    f.push(self.type_expression()?);
                    self.expect("]")?;
                    self.expect(":")?;
                    f.push(self.type_expression()?);
                } else if self.token().kind == TokenKind::Name && self.at_next(":") {
                    f.push(self.name()?);
                    self.expect(":")?;
                    f.push(self.type_expression()?);
                } else {
                    f.push(self.type_expression()?);
                }
                parts.push(self.node(Kind::TypeField, at, f));
                if !self.eat(",") && !self.eat(";") {
                    break;
                }
            }
            self.expect("}")?;
        } else if self.at("typeof") && self.at_next("(") {
            self.bump();
            self.expect("(")?;
            parts.push(self.expression(0)?);
            self.expect(")")?;
        } else if self.token().kind == TokenKind::Name || self.token().kind == TokenKind::String {
            if self.token().kind == TokenKind::String
                || self.at("nil")
                || self.at("true")
                || self.at("false")
            {
                self.bump();
            } else {
                self.name()?;
            }
            if self.eat(".") {
                parts.push(self.name()?);
            }
            if self.eat("<") {
                let at = self.tokens[self.pos - 1].span.start;
                let mut params = vec![];
                if !self.at(">") {
                    loop {
                        params.push(self.return_type()?);
                        if !self.eat(",") {
                            break;
                        }
                    }
                }
                self.expect(">")?;
                parts.push(self.node(Kind::TypeArguments, at, params));
            }
            if self.at("...") {
                if !allow_pack {
                    return Err(self.error("此处不允许类型包"));
                }
                self.bump();
            }
        } else {
            return Err(self.error("需要类型"));
        }
        let mut node = self.node(Kind::Type, start, parts);
        while self.eat("?") {
            node = self.node(Kind::TypeOptional, start, vec![node]);
        }
        Ok(node)
    }
}

// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{Parser, Result};
use crate::ast::{Kind, Node};
use crate::lexer::TokenKind;

impl Parser<'_> {
    pub(super) fn attributes(&mut self) -> Result<Vec<Node>> {
        let mut attrs = Vec::new();
        let mut names: Vec<Vec<u8>> = Vec::new();
        while self.eat("@") {
            let start = self.tokens[self.pos - 1].span.start;
            if self.offset() != self.end() {
                return Err(self.error("@ 后不能有空白"));
            }
            if self.eat("[") {
                if self.at("]") {
                    return Err(self.error("属性列表不能为空"));
                }
                loop {
                    let at = self.offset();
                    let name = self.name()?;
                    let mut children = vec![name];
                    if self.at("(") || self.at("{") || self.token().kind == TokenKind::String {
                        children.extend(self.arguments()?);
                    }
                    self.validate_attribute(&children, &mut names)?;
                    attrs.push(self.node(Kind::Attribute, at, children));
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("]")?;
            } else {
                let name = self.name()?;
                let children = vec![name];
                self.validate_attribute(&children, &mut names)?;
                attrs.push(self.node(Kind::Attribute, start, children));
            }
        }
        Ok(attrs)
    }

    fn validate_attribute(&self, children: &[Node], seen: &mut Vec<Vec<u8>>) -> Result<()> {
        let name = &self.source[children[0].span.clone()];
        if ![b"native".as_slice(), b"checked", b"deprecated"].contains(&name) {
            return Err(self.error("无效的属性名称"));
        }
        if seen.iter().any(|n| n == name) {
            return Err(self.error("属性不能重复"));
        }
        seen.push(name.to_vec());
        let args = &children[1..];
        if args.iter().any(|arg| !self.attribute_literal(arg)) {
            return Err(self.error("属性参数必须是字面量"));
        }
        if name == b"deprecated" && !args.is_empty() {
            if args.len() != 1 || args[0].kind != Kind::Table {
                return Err(self.error("deprecated 只接受一个表参数"));
            }
            for field in &args[0].children {
                if field.kind != Kind::TableRecord
                    || field.children.len() != 2
                    || field.children[0].kind != Kind::Name
                    || field.children[1].kind != Kind::String
                {
                    return Err(self.error("deprecated 表只接受字符串字段 use 和 reason"));
                }
                let key = &self.source[field.children[0].span.clone()];
                if key != b"use" && key != b"reason" {
                    return Err(self.error("无效的 deprecated 属性字段"));
                }
            }
        }
        Ok(())
    }
    fn attribute_literal(&self, node: &Node) -> bool {
        match node.kind {
            Kind::Nil | Kind::Boolean | Kind::Number | Kind::String => true,
            Kind::Interpolation => node.children.iter().all(|child| child.kind == Kind::String),
            Kind::Table => node.children.iter().all(|field| {
                field.kind != Kind::TableIndex
                    && field
                        .children
                        .last()
                        .is_some_and(|value| self.attribute_literal(value))
            }),
            _ => false,
        }
    }
}

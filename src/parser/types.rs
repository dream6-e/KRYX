// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{Parser, Result};
use crate::ast::{Kind, Node};
use crate::lexer::TokenKind;

impl Parser<'_> {
    pub(super) fn generics(&mut self, allow_defaults: bool) -> Result<Node> {
        let start = self.offset();
        self.expect("<")?;
        let mut parts = vec![];
        let mut seen_pack = false;
        let mut seen_default = false;
        loop {
            let at = self.offset();
            let mut inner = vec![self.name()?];
            let pack = self.eat("...");
            if seen_pack && !pack {
                return Err(self.error("普通泛型必须在泛型类型包之前"));
            }
            seen_pack |= pack;
            let has_default = self.eat("=");
            if has_default && !allow_defaults {
                return Err(self.error("此处不允许泛型默认值"));
            }
            if seen_default && !has_default {
                return Err(self.error("默认泛型参数之后必须有默认值"));
            }
            if has_default {
                seen_default = true;
                inner.push(if pack {
                    self.return_type()?
                } else {
                    self.type_expression()?
                });
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
    pub(super) fn type_parameter(&mut self) -> Result<Node> {
        let ty = self.return_type()?;
        let mut work = vec![&ty];
        while let Some(node) = work.pop() {
            if matches!(node.kind, Kind::TypeOptional | Kind::TypeBinary(_)) {
                if node
                    .children
                    .iter()
                    .any(|child| matches!(child.kind, Kind::TypePack | Kind::TypeTuple))
                {
                    return Err(self.error("类型包不能带类型后缀或运算符"));
                }
                work.extend(node.children.iter());
            }
        }
        Ok(ty)
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
            if op == "&" && lhs.kind == Kind::TypeOptional {
                return Err(self.error("可选类型和交叉类型不能直接混用"));
            }
            operator = Some(op.clone());
            self.bump();
            let rhs = self.type_atom(false)?;
            if op == "&" && rhs.kind == Kind::TypeOptional {
                return Err(self.error("可选类型和交叉类型不能直接混用"));
            }
            lhs = self.node(Kind::TypeBinary(op), start, vec![lhs, rhs]);
        }
        Ok(lhs)
    }
    fn type_atom(&mut self, allow_pack: bool) -> Result<Node> {
        let start = self.offset();
        let mut parts = vec![];
        let mut is_pack = false;
        let mut is_function = false;
        let mut is_tuple = false;
        let mut is_typeof = false;
        if self.at("...") {
            if !allow_pack {
                return Err(self.error("此处不允许类型包"));
            }
            self.bump();
            is_pack = true;
            parts.push(self.type_expression()?);
        } else if self.at("<") {
            parts.push(self.generics(false)?);
            if !self.at("(") {
                return Err(self.error("泛型函数类型需要参数列表"));
            }
            let function = self.type_atom(false)?;
            if function.kind != Kind::TypeFunctionExpression {
                return Err(self.error("泛型函数类型需要返回类型"));
            }
            parts.push(function);
        } else if self.eat("(") {
            let mut has_names = false;
            let mut has_type_pack = false;
            if !self.at(")") {
                loop {
                    let at = self.offset();
                    let mut p = vec![];
                    if self.token().kind == TokenKind::Name && self.at_next(":") {
                        has_names = true;
                        p.push(self.name()?);
                        self.expect(":")?;
                    }
                    let pack = p.is_empty()
                        && (self.at("...")
                            || (self.token().kind == TokenKind::Name && self.at_next("...")));
                    let ty = if pack {
                        self.return_type()?
                    } else {
                        self.type_expression()?
                    };
                    if pack && !matches!(ty.kind, Kind::TypePack) {
                        return Err(self.error("类型包不能带类型后缀或运算符"));
                    }
                    let tail = matches!(ty.kind, Kind::TypePack);
                    has_type_pack |= tail;
                    p.push(ty);
                    parts.push(self.node(Kind::Parameter, at, p));
                    if tail && self.at(",") {
                        return Err(self.error("可变类型包必须在列表末尾"));
                    }
                    if !self.eat(",") {
                        break;
                    }
                }
            }
            self.expect(")")?;
            if self.eat("->") {
                is_function = true;
                parts.push(self.return_type()?);
            } else if !allow_pack && (parts.len() != 1 || has_names || has_type_pack) {
                return Err(self.error("此处的类型列表需要 `->`"));
            } else {
                is_tuple = parts.len() != 1 || has_type_pack;
            }
        } else if self.eat("{") {
            let mut has_indexer = false;
            while !self.at("}") {
                let at = self.offset();
                let mut f = vec![];
                if (self.at("read") || self.at("write")) && !self.at_next(":") {
                    f.push(self.name()?);
                }
                if self.eat("[") {
                    let string_key = self.token().kind == TokenKind::String && self.at_next("]");
                    if string_key {
                        let key = self.token().span.clone();
                        if self.string_contains_nul(key) {
                            return Err(self.error("表类型字段名不能包含零字节"));
                        }
                    } else {
                        if has_indexer {
                            return Err(self.error("表类型只能有一个索引器"));
                        }
                        has_indexer = true;
                    }
                    f.push(self.type_expression()?);
                    self.expect("]")?;
                    self.expect(":")?;
                    f.push(self.type_expression()?);
                } else if self.token().kind == TokenKind::Name && self.at_next(":") {
                    f.push(self.name()?);
                    self.expect(":")?;
                    f.push(self.type_expression()?);
                } else {
                    if !parts.is_empty() || has_indexer {
                        return Err(self.error("数组类型不能混合其他字段"));
                    }
                    f.push(self.type_expression()?);
                    parts.push(self.node(Kind::TypeField, at, f));
                    break;
                }
                parts.push(self.node(Kind::TypeField, at, f));
                if !self.eat(",") && !self.eat(";") {
                    break;
                }
            }
            self.expect("}")?;
        } else if self.at("typeof") && !self.at_next(".") {
            is_typeof = true;
            self.bump();
            self.expect("(")?;
            parts.push(self.expression(0)?);
            self.expect(")")?;
        } else if self.token().kind == TokenKind::Name || self.token().kind == TokenKind::String {
            let singleton = self.token().kind == TokenKind::String
                || self.at("nil")
                || self.at("true")
                || self.at("false");
            if singleton {
                self.bump();
            } else {
                self.name()?;
            }
            if !singleton && self.eat(".") {
                parts.push(self.name()?);
            }
            if !singleton && self.eat("<") {
                let at = self.tokens[self.pos - 1].span.start;
                let mut params = vec![];
                if !self.at(">") {
                    loop {
                        params.push(self.type_parameter()?);
                        if !self.eat(",") {
                            break;
                        }
                    }
                }
                self.expect(">")?;
                parts.push(self.node(Kind::TypeArguments, at, params));
            }
            if !singleton && self.at("...") {
                if !allow_pack {
                    return Err(self.error("此处不允许类型包"));
                }
                self.bump();
                is_pack = true;
            }
        } else {
            return Err(self.error("需要类型"));
        }
        let mut node = self.node(
            if is_typeof {
                Kind::TypeOf
            } else if is_tuple {
                Kind::TypeTuple
            } else if is_pack {
                Kind::TypePack
            } else if is_function {
                Kind::TypeFunctionExpression
            } else {
                Kind::Type
            },
            start,
            parts,
        );
        while self.eat("?") {
            node = self.node(Kind::TypeOptional, start, vec![node]);
        }
        Ok(node)
    }
}

impl Parser<'_> {
    fn string_contains_nul(&self, span: std::ops::Range<usize>) -> bool {
        let raw = &self.source[span];
        if raw.contains(&0) {
            return true;
        }
        if !matches!(raw.first(), Some(b'\'' | b'"')) {
            return false;
        }
        let mut i = 1;
        while i + 1 < raw.len() {
            if raw[i] != b'\\' {
                i += 1;
                continue;
            }
            i += 1;
            let c = raw[i];
            i += 1;
            if c.is_ascii_digit() {
                let mut value = u32::from(c - b'0');
                for _ in 0..2 {
                    if i < raw.len() && raw[i].is_ascii_digit() {
                        value = value * 10 + u32::from(raw[i] - b'0');
                        i += 1;
                    } else {
                        break;
                    }
                }
                if value == 0 {
                    return true;
                }
            } else if c == b'x' {
                if raw.get(i..i + 2) == Some(b"00") {
                    return true;
                }
                i += 2;
            } else if c == b'u' {
                i += 1;
                let start = i;
                while i < raw.len() && raw[i] != b'}' {
                    i += 1;
                }
                if raw[start..i].iter().all(|&d| d == b'0') {
                    return true;
                }
                i += 1;
            } else if c == b'z' {
                while i < raw.len() && (raw[i].is_ascii_whitespace() || raw[i] == 0x0b) {
                    i += 1;
                }
            }
        }
        false
    }
}

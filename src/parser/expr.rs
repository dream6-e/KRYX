// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{Parser, Result};
use crate::ast::{Kind, Node};
use crate::lexer::TokenKind;

impl Parser<'_> {
    pub(super) fn expression(&mut self, min: u8) -> Result<Node> {
        self.enter()?;
        let result = self.expression_inner(min);
        self.depth -= 1;
        result
    }
    fn expression_inner(&mut self, min: u8) -> Result<Node> {
        let start = self.offset();
        let mut lhs = if self.at("not") || self.at("-") || self.at("#") {
            let op = String::from_utf8_lossy(self.text()).into_owned();
            self.bump();
            let rhs = self.expression(7)?;
            self.node(Kind::Unary(op), start, vec![rhs])
        } else {
            self.simple_expression()?
        };
        loop {
            let (op, left, right) = match self.text() {
                b"or" => ("or", 1, 2),
                b"and" => ("and", 2, 3),
                b"<" => ("<", 3, 4),
                b">" => (">", 3, 4),
                b"<=" => ("<=", 3, 4),
                b">=" => (">=", 3, 4),
                b"~=" => ("~=", 3, 4),
                b"==" => ("==", 3, 4),
                b".." => ("..", 4, 4),
                b"+" => ("+", 5, 6),
                b"-" => ("-", 5, 6),
                b"*" => ("*", 6, 7),
                b"/" => ("/", 6, 7),
                b"//" => ("//", 6, 7),
                b"%" => ("%", 6, 7),
                b"^" => ("^", 8, 8),
                _ => break,
            };
            if left < min {
                break;
            }
            self.bump();
            let rhs = self.expression(right)?;
            lhs = self.node(Kind::Binary(op.into()), start, vec![lhs, rhs]);
        }
        Ok(lhs)
    }
    fn simple_expression(&mut self) -> Result<Node> {
        let start = self.offset();
        let mut node = if self.at("nil") {
            self.bump();
            self.node(Kind::Nil, start, vec![])
        } else if self.at("true") || self.at("false") {
            self.bump();
            self.node(Kind::Boolean, start, vec![])
        } else if self.at("...") {
            if !self.vararg {
                return Err(self.error("不能在非可变参数函数中使用 ..."));
            }
            self.bump();
            self.node(Kind::Varargs, start, vec![])
        } else if self.token().kind == TokenKind::Number {
            self.bump();
            self.node(Kind::Number, start, vec![])
        } else if self.token().kind == TokenKind::String {
            self.bump();
            self.node(Kind::String, start, vec![])
        } else if self.eat("`") {
            self.interpolation(start)?
        } else if self.eat("{") {
            self.table(start)?
        } else if self.eat("function") {
            self.function_body(start)?
        } else if self.at("@") {
            let mut attrs = self.attributes()?;
            self.expect("function")?;
            attrs.push(self.function_body(start)?);
            self.node(Kind::Attributed, start, attrs)
        } else if self.eat("if") {
            self.if_expression(start)?
        } else if self.eat("(") {
            let n = self.expression(0)?;
            self.expect(")")?;
            self.node(Kind::Parenthesized, start, vec![n])
        } else {
            self.name()?
        };
        // Prefix suffixes are only legal on identifiers and parenthesized expressions.
        if matches!(node.kind, Kind::Name | Kind::Parenthesized) {
            loop {
                if self.at("<") && self.at_next("<") {
                    self.bump();
                    self.bump();
                    let mut children = vec![node];
                    if !self.at(">") {
                        children.push(self.type_parameter()?);
                        while self.eat(",") {
                            children.push(self.type_parameter()?);
                        }
                    }
                    self.expect(">")?;
                    self.expect(">")?;
                    node = self.node(Kind::TypeInstantiation, start, children);
                } else if self.eat(".") {
                    let field = self.name()?;
                    node = self.node(Kind::Field, start, vec![node, field]);
                } else if self.eat("[") {
                    let index = self.expression(0)?;
                    self.expect("]")?;
                    node = self.node(Kind::Index, start, vec![node, index]);
                } else if self.eat(":") {
                    let method = self.name()?;
                    let mut children = vec![node, method];
                    if self.at("<") && self.at_next("<") {
                        let at = self.offset();
                        self.bump();
                        self.bump();
                        let mut types = vec![];
                        if !self.at(">") {
                            types.push(self.type_parameter()?);
                            while self.eat(",") {
                                types.push(self.type_parameter()?);
                            }
                        }
                        self.expect(">")?;
                        self.expect(">")?;
                        children.push(self.node(Kind::TypeArguments, at, types));
                    }
                    if self.at("(") && self.source[self.end()..self.offset()].contains(&b'\n') {
                        return Err(self.error("跨行调用有歧义，请使用分号"));
                    }
                    children.extend(self.arguments()?);
                    node = self.node(Kind::MethodCall, start, children);
                } else if self.at("(") || self.at("{") || self.token().kind == TokenKind::String {
                    if self.at("(") && self.source[node.span.end..self.offset()].contains(&b'\n') {
                        return Err(self.error("跨行调用有歧义，请使用分号"));
                    }
                    let mut children = vec![node];
                    children.extend(self.arguments()?);
                    node = self.node(Kind::Call, start, children);
                } else {
                    break;
                }
            }
        }
        if self.eat("::") {
            let ty = self.type_expression()?;
            node = self.node(Kind::TypeAssertion, start, vec![node, ty]);
        }
        Ok(node)
    }
    pub(super) fn arguments(&mut self) -> Result<Vec<Node>> {
        if self.eat("(") {
            let args = if self.at(")") { vec![] } else { self.list()? };
            self.expect(")")?;
            Ok(args)
        } else if self.eat("{") {
            let start = self.tokens[self.pos - 1].span.start;
            Ok(vec![self.table(start)?])
        } else if self.token().kind == TokenKind::String {
            let start = self.offset();
            self.bump();
            Ok(vec![self.node(Kind::String, start, vec![])])
        } else {
            Err(self.error("需要函数调用参数"))
        }
    }
    fn table(&mut self, start: usize) -> Result<Node> {
        let mut fields = vec![];
        while !self.at("}") {
            let at = self.offset();
            let mut children = vec![];
            let kind;
            if self.eat("[") {
                kind = Kind::TableIndex;
                children.push(self.expression(0)?);
                self.expect("]")?;
                self.expect("=")?;
                children.push(self.expression(0)?);
            } else if self.token().kind == TokenKind::Name && self.at_next("=") {
                kind = Kind::TableRecord;
                children.push(self.name()?);
                self.expect("=")?;
                children.push(self.expression(0)?);
            } else {
                kind = Kind::TableArray;
                children.push(self.expression(0)?);
            }
            fields.push(self.node(kind, at, children));
            if !self.eat(",") && !self.eat(";") {
                break;
            }
        }
        self.expect("}")?;
        Ok(self.node(Kind::Table, start, fields))
    }
    fn interpolation(&mut self, start: usize) -> Result<Node> {
        let mut parts = vec![];
        while !self.at("`") {
            if self.token().kind == TokenKind::InterpolationText {
                let at = self.offset();
                self.bump();
                parts.push(self.node(Kind::String, at, vec![]));
            } else if self.eat("{") {
                parts.push(self.expression(0)?);
                self.expect("}")?;
            } else {
                return Err(self.error("无效的插值字符串"));
            }
        }
        self.expect("`")?;
        Ok(self.node(Kind::Interpolation, start, parts))
    }
    fn if_expression(&mut self, start: usize) -> Result<Node> {
        let mut children = vec![self.condition()?];
        self.expect("then")?;
        children.push(self.expression(0)?);
        while self.eat("elseif") {
            children.push(self.condition()?);
            self.expect("then")?;
            children.push(self.expression(0)?);
        }
        self.expect("else")?;
        children.push(self.expression(0)?);
        Ok(self.node(Kind::IfExpression, start, children))
    }
    pub(super) fn function_body(&mut self, start: usize) -> Result<Node> {
        let mut parts = vec![];
        if self.at("<") {
            parts.push(self.generics(false)?);
        }
        let at = self.offset();
        self.expect("(")?;
        let mut params = vec![];
        let mut vararg = false;
        if !self.at(")") {
            loop {
                let p = self.offset();
                let mut children = if self.eat("...") {
                    vec![self.node(Kind::Varargs, p, vec![])]
                } else {
                    vec![self.name()?]
                };
                let variadic = matches!(children[0].kind, Kind::Varargs);
                if self.eat(":") {
                    children.push(if variadic {
                        self.return_type()?
                    } else {
                        self.type_expression()?
                    });
                }
                vararg |= variadic;
                params.push(self.node(Kind::Parameter, p, children));
                if variadic || !self.eat(",") {
                    break;
                }
            }
        }
        self.expect(")")?;
        parts.push(self.node(Kind::Parameters, at, params));
        if self.eat(":") {
            parts.push(self.return_type()?);
        }
        let old_loops = self.loops;
        let old_vararg = self.vararg;
        self.loops = 0;
        self.vararg = vararg;
        let body = self.block(&["end"]);
        self.loops = old_loops;
        self.vararg = old_vararg;
        parts.push(body?);
        self.expect("end")?;
        Ok(self.node(Kind::Function, start, parts))
    }
}

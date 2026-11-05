// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use super::{Parser, Result};
use crate::ast::{Kind, Node};

impl Parser<'_> {
    pub(super) fn block(&mut self, stops: &[&str]) -> Result<Node> {
        self.enter()?;
        let start = self.offset();
        let mut children = vec![];
        let result = (|| {
            while !self.eof() && !stops.iter().any(|s| self.at(s)) {
                if self.eat(";") {
                    continue;
                }
                let statement = self.statement()?;
                let terminal =
                    matches!(statement.kind, Kind::Return | Kind::Break | Kind::Continue);
                children.push(statement);
                self.eat(";");
                if terminal && !self.eof() && !stops.iter().any(|s| self.at(s)) {
                    return Err(self.error("return/break/continue 之后不能再有语句"));
                }
            }
            Ok(self.node(Kind::Block, start, children))
        })();
        self.depth -= 1;
        result
    }
    fn loop_body(&mut self, stops: &[&str]) -> Result<Node> {
        self.loops += 1;
        let r = self.block(stops);
        self.loops -= 1;
        r
    }
    fn statement(&mut self) -> Result<Node> {
        let start = self.offset();
        if self.at("@") {
            let mut attrs = self.attributes()?;
            if !self.at("function") && !self.at("local") && !self.at("const") {
                return Err(self.error("属性只能用于函数声明"));
            }
            let declaration = self.statement()?;
            if !matches!(
                declaration.kind,
                Kind::FunctionStatement | Kind::LocalFunction
            ) {
                return Err(self.error("属性只能用于函数声明"));
            }
            attrs.push(declaration);
            return Ok(self.node(Kind::Attributed, start, attrs));
        }
        if self.at("export")
            && (self.at_next("local") || self.at_next("function") || self.at_next("const"))
        {
            self.bump();
            let declaration = self.statement()?;
            return Ok(self.node(Kind::Export, start, vec![declaration]));
        }
        let is_const = self.at("const")
            && self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|t| t.kind == crate::lexer::TokenKind::Name);
        if self.eat("local") || (is_const && self.eat("const")) {
            if self.eat("function") {
                let name = self.name()?;
                let body = self.function_body(start)?;
                return Ok(self.node(Kind::LocalFunction, start, vec![name, body]));
            }
            let mut children = vec![];
            loop {
                children.push(self.binding()?);
                if !self.eat(",") {
                    break;
                }
            }
            let bindings_end = self.end();
            let mut parts = vec![Node {
                kind: Kind::BindingList,
                span: children[0].span.start..bindings_end,
                children,
            }];
            if self.eat("=") {
                let at = self.offset();
                let values = self.list()?;
                parts.push(self.node(Kind::ValueList, at, values));
            }
            return Ok(self.node(
                if is_const { Kind::Const } else { Kind::Local },
                start,
                parts,
            ));
        }
        if self.eat("return") {
            let children = if self.eof()
                || ["end", "else", "elseif", "until", ";"]
                    .iter()
                    .any(|x| self.at(x))
            {
                vec![]
            } else {
                self.list()?
            };
            return Ok(self.node(Kind::Return, start, children));
        }
        if self.at("break") || self.at("continue") {
            let is_break = self.at("break");
            // `continue` is contextual, and can also be an identifier/call.
            if is_break
                || !["=", "(", ".", "[", ":", ",", "+=", "-="]
                    .iter()
                    .any(|s| self.at_next(s))
            {
                if self.loops == 0 {
                    return Err(self.error("break/continue 必须位于循环内"));
                }
                self.bump();
                return Ok(self.node(
                    if is_break {
                        Kind::Break
                    } else {
                        Kind::Continue
                    },
                    start,
                    vec![],
                ));
            }
        }
        if self.eat("do") {
            let body = self.block(&["end"])?;
            self.expect("end")?;
            return Ok(self.node(Kind::Do, start, vec![body]));
        }
        if self.eat("while") {
            let cond = self.expression(0)?;
            self.expect("do")?;
            let body = self.loop_body(&["end"])?;
            self.expect("end")?;
            return Ok(self.node(Kind::While, start, vec![cond, body]));
        }
        if self.eat("repeat") {
            let body = self.loop_body(&["until"])?;
            self.expect("until")?;
            let cond = self.expression(0)?;
            return Ok(self.node(Kind::Repeat, start, vec![body, cond]));
        }
        if self.eat("if") {
            let mut parts = vec![];
            loop {
                let at = self.offset();
                let cond = self.condition()?;
                self.expect("then")?;
                let body = self.block(&["elseif", "else", "end"])?;
                parts.push(self.node(Kind::Branch, at, vec![cond, body]));
                if !self.eat("elseif") {
                    break;
                }
            }
            if self.eat("else") {
                parts.push(self.block(&["end"])?);
            }
            self.expect("end")?;
            return Ok(self.node(Kind::If, start, parts));
        }
        if self.eat("for") {
            let first = self.binding()?;
            let mut parts = vec![first];
            let kind = if self.eat("=") {
                parts.push(self.expression(0)?);
                self.expect(",")?;
                parts.push(self.expression(0)?);
                if self.eat(",") {
                    parts.push(self.expression(0)?);
                }
                Kind::ForNumeric
            } else {
                while self.eat(",") {
                    parts.push(self.binding()?);
                }
                self.expect("in")?;
                parts.extend(self.list()?);
                Kind::ForGeneric
            };
            self.expect("do")?;
            parts.push(self.loop_body(&["end"])?);
            self.expect("end")?;
            return Ok(self.node(kind, start, parts));
        }
        if self.eat("function") {
            let target_start = self.offset();
            let mut target = self.name()?;
            while self.eat(".") {
                let name = self.name()?;
                target = self.node(Kind::Field, target_start, vec![target, name]);
            }
            if self.eat(":") {
                let name = self.name()?;
                target = self.node(Kind::Field, target_start, vec![target, name]);
            }
            let body = self.function_body(start)?;
            return Ok(self.node(Kind::FunctionStatement, start, vec![target, body]));
        }
        if (self.at("type")
            && self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|t| t.kind == crate::lexer::TokenKind::Name))
            || (self.at("export") && self.at_next("type"))
        {
            self.eat("export");
            self.expect("type")?;
            if self.eat("function") {
                let name = self.name()?;
                let body = self.function_body(start)?;
                return Ok(self.node(Kind::TypeFunction, start, vec![name, body]));
            }
            let mut parts = vec![self.name()?];
            if self.at("<") {
                parts.push(self.generics()?);
            }
            self.expect("=")?;
            parts.push(self.type_expression()?);
            return Ok(self.node(Kind::TypeAlias, start, parts));
        }
        let first = self.expression(0)?;
        if matches!(first.kind, Kind::Call | Kind::MethodCall) && !self.at(",") && !self.at("=") {
            return Ok(self.node(Kind::CallStatement, start, vec![first]));
        }
        let valid_lvalue = |n: &Node| matches!(n.kind, Kind::Name | Kind::Field | Kind::Index);
        if !valid_lvalue(&first) {
            return Err(self.error("需要赋值目标或函数调用"));
        }
        if ["+=", "-=", "*=", "/=", "//=", "%=", "^=", "..="]
            .iter()
            .any(|s| self.at(s))
        {
            let op = String::from_utf8_lossy(self.text()).into_owned();
            self.bump();
            let rhs = self.expression(0)?;
            return Ok(self.node(Kind::CompoundAssignment(op), start, vec![first, rhs]));
        }
        let mut targets = vec![first];
        while self.eat(",") {
            let n = self.expression(0)?;
            if !valid_lvalue(&n) {
                return Err(self.error("无效的赋值目标"));
            }
            targets.push(n);
        }
        let targets = self.node(Kind::TargetList, start, targets);
        self.expect("=")?;
        let at = self.offset();
        let values = self.list()?;
        let values = self.node(Kind::ValueList, at, values);
        Ok(self.node(Kind::Assignment, start, vec![targets, values]))
    }
    pub(super) fn condition(&mut self) -> Result<Node> {
        let at = self.offset();
        if (self.at("local") || self.at("const"))
            && !self.at_next("then")
            && self
                .tokens
                .get(self.pos + 1)
                .is_some_and(|t| t.kind == crate::lexer::TokenKind::Name)
        {
            self.bump();
            let name = self.name()?;
            self.expect("=")?;
            let expr = self.expression(0)?;
            Ok(self.node(Kind::ConditionalBinding, at, vec![name, expr]))
        } else {
            self.expression(0)
        }
    }
    pub(super) fn attributes(&mut self) -> Result<Vec<Node>> {
        let mut attrs = vec![];
        while self.eat("@") {
            let start = self.tokens[self.pos - 1].span.start;
            if self.eat("[") {
                loop {
                    let at = self.offset();
                    let name = self.name()?;
                    let mut children = vec![name];
                    if self.eat("(") {
                        if !self.at(")") {
                            children.extend(self.list()?);
                        }
                        self.expect(")")?;
                    }
                    attrs.push(self.node(Kind::Attribute, at, children));
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("]")?;
            } else {
                let name = self.name()?;
                attrs.push(self.node(Kind::Attribute, start, vec![name]));
            }
        }
        Ok(attrs)
    }
    fn binding(&mut self) -> Result<Node> {
        let start = self.offset();
        let mut parts = vec![self.name()?];
        if self.eat(":") {
            parts.push(self.type_expression()?);
        }
        Ok(self.node(Kind::Parameter, start, parts))
    }
}

// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Name,
    Number,
    String,
    InterpolationText,
    Symbol,
    Whitespace,
    Comment,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub offset: usize,
    pub message: String,
}

#[derive(Clone, Copy)]
enum Mode {
    Text,
    Expression(usize),
}

pub fn lex(source: &[u8]) -> Result<Vec<Token>, LexError> {
    let mut l = Lexer {
        source,
        pos: 0,
        tokens: Vec::new(),
        modes: Vec::new(),
    };
    l.run()?;
    Ok(l.tokens)
}

struct Lexer<'a> {
    source: &'a [u8],
    pos: usize,
    tokens: Vec<Token>,
    modes: Vec<Mode>,
}
impl Lexer<'_> {
    fn byte(&self, n: usize) -> Option<u8> {
        self.source.get(self.pos + n).copied()
    }
    fn starts(&self, s: &[u8]) -> bool {
        self.source[self.pos..].starts_with(s)
    }
    fn push(&mut self, kind: TokenKind, start: usize) {
        self.tokens.push(Token {
            kind,
            span: start..self.pos,
        });
    }
    fn error<T>(&self, start: usize, msg: &str) -> Result<T, LexError> {
        Err(LexError {
            offset: start,
            message: msg.into(),
        })
    }
    fn long_open(&self, at: usize) -> Option<(usize, usize)> {
        if self.source.get(at) != Some(&b'[') {
            return None;
        }
        let mut i = at + 1;
        while self.source.get(i) == Some(&b'=') {
            i += 1;
        }
        (self.source.get(i) == Some(&b'[')).then_some((i - at - 1, i + 1))
    }
    fn long_string(&mut self, start: usize, eq: usize, content: usize) -> Result<(), LexError> {
        self.pos = content;
        while self.pos < self.source.len() {
            if self.byte(0) == Some(b']') {
                let mut i = self.pos + 1;
                while i < self.source.len() && self.source[i] == b'=' {
                    i += 1;
                }
                if i - self.pos - 1 == eq && self.source.get(i) == Some(&b']') {
                    self.pos = i + 1;
                    return Ok(());
                }
            }
            self.pos += 1;
        }
        self.error(start, "未结束的长字符串或长注释")
    }
    fn escape(&mut self, start: usize) -> Result<(), LexError> {
        self.pos += 1;
        let Some(next) = self.byte(0) else {
            return self.error(start, "未结束的转义");
        };
        self.pos += 1;
        if next == b'x' {
            for _ in 0..2 {
                if !self.byte(0).is_some_and(|c| c.is_ascii_hexdigit()) {
                    return self.error(start, "无效的十六进制转义");
                }
                self.pos += 1;
            }
        } else if next == b'u' {
            if self.byte(0) != Some(b'{') {
                return self.error(start, "无效的 Unicode 转义");
            }
            self.pos += 1;
            let digits = self.pos;
            let mut value = 0u32;
            while let Some(c) = self.byte(0).filter(|c| c.is_ascii_hexdigit()) {
                let d = (c as char).to_digit(16).unwrap();
                value = value
                    .checked_mul(16)
                    .and_then(|v| v.checked_add(d))
                    .unwrap_or(u32::MAX);
                self.pos += 1;
            }
            if self.pos == digits || value > 0x10ffff || self.byte(0) != Some(b'}') {
                return self.error(start, "无效的 Unicode 转义");
            }
            self.pos += 1;
        } else if next.is_ascii_digit() {
            let mut value = u32::from(next - b'0');
            for _ in 0..2 {
                if let Some(c) = self.byte(0).filter(|c| c.is_ascii_digit()) {
                    value = value * 10 + u32::from(c - b'0');
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if value > 255 {
                return self.error(start, "十进制转义超出范围");
            }
        }
        if next == b'\r' && self.byte(0) == Some(b'\n') {
            self.pos += 1;
        }
        if next == b'z' {
            while self
                .byte(0)
                .is_some_and(|x| (x.is_ascii_whitespace() || x == 0x0b))
            {
                self.pos += 1;
            }
        }
        Ok(())
    }
    fn quoted(&mut self, start: usize, quote: u8) -> Result<(), LexError> {
        self.pos += 1;
        while let Some(c) = self.byte(0) {
            if c == quote {
                self.pos += 1;
                return Ok(());
            }
            if c == b'\n' || c == b'\r' {
                return self.error(start, "字符串中出现未转义的换行");
            }
            if c == b'\\' {
                self.escape(start)?;
            } else {
                self.pos += 1;
            }
        }
        self.error(start, "未结束的字符串")
    }
    fn interpolation_text(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        while let Some(c) = self.byte(0) {
            if c == b'\\' {
                self.escape(start)?;
            } else if c == b'`' || c == b'{' {
                if c == b'{' && self.byte(1) == Some(b'{') {
                    return self.error(self.pos, "插值字符串不能使用双花括号");
                }
                if self.pos > start {
                    self.push(TokenKind::InterpolationText, start);
                }
                let at = self.pos;
                self.pos += 1;
                self.push(TokenKind::Symbol, at);
                if c == b'`' {
                    self.modes.pop();
                } else {
                    self.modes.push(Mode::Expression(0));
                }
                return Ok(());
            } else if c == b'\n' || c == b'\r' {
                return self.error(self.pos, "插值字符串中出现未转义的换行");
            } else {
                self.pos += 1;
            }
        }
        self.error(start, "未结束的插值字符串")
    }
    fn run(&mut self) -> Result<(), LexError> {
        while self.pos < self.source.len() {
            if matches!(self.modes.last(), Some(Mode::Text)) {
                self.interpolation_text()?;
                continue;
            }
            let start = self.pos;
            let c = self.byte(0).unwrap();
            if c.is_ascii_whitespace() || c == 0x0b {
                self.pos += 1;
                while self
                    .byte(0)
                    .is_some_and(|c| (c.is_ascii_whitespace() || c == 0x0b))
                {
                    self.pos += 1;
                }
                self.push(TokenKind::Whitespace, start);
                continue;
            }
            if self.starts(b"--") {
                self.pos += 2;
                if let Some((eq, content)) = self.long_open(self.pos) {
                    self.long_string(start, eq, content)?;
                } else {
                    while self.byte(0).is_some_and(|b| b != b'\r' && b != b'\n') {
                        self.pos += 1;
                    }
                }
                self.push(TokenKind::Comment, start);
                continue;
            }
            if c == b'\'' || c == b'"' {
                self.quoted(start, c)?;
                self.push(TokenKind::String, start);
                continue;
            }
            if let Some((eq, content)) = self.long_open(self.pos) {
                self.long_string(start, eq, content)?;
                self.push(TokenKind::String, start);
                continue;
            }
            if c.is_ascii_alphabetic() || c == b'_' {
                self.pos += 1;
                while self
                    .byte(0)
                    .is_some_and(|x| x.is_ascii_alphanumeric() || x == b'_')
                {
                    self.pos += 1;
                }
                self.push(TokenKind::Name, start);
                continue;
            }
            if c.is_ascii_digit() || (c == b'.' && self.byte(1).is_some_and(|x| x.is_ascii_digit()))
            {
                self.pos += 1;
                while self
                    .byte(0)
                    .is_some_and(|x| x.is_ascii_digit() || x == b'.' || x == b'_')
                {
                    self.pos += 1;
                }
                if matches!(self.byte(0), Some(b'e' | b'E')) {
                    self.pos += 1;
                    if matches!(self.byte(0), Some(b'+' | b'-')) {
                        self.pos += 1;
                    }
                }
                while self
                    .byte(0)
                    .is_some_and(|x| x.is_ascii_alphanumeric() || x == b'_')
                {
                    self.pos += 1;
                }
                let raw = self.source[start..self.pos]
                    .iter()
                    .copied()
                    .filter(|c| *c != b'_')
                    .collect::<Vec<_>>();
                let integer = raw.last() == Some(&b'i');
                let raw = if integer {
                    &raw[..raw.len() - 1]
                } else {
                    &raw[..]
                };
                let valid = if raw.starts_with(b"0x") || raw.starts_with(b"0X") {
                    raw.len() > 2 && raw[2..].iter().all(|c| c.is_ascii_hexdigit())
                } else if raw.starts_with(b"0b") || raw.starts_with(b"0B") {
                    raw.len() > 2 && raw[2..].iter().all(|c| matches!(c, b'0' | b'1'))
                } else if integer {
                    !raw.is_empty() && raw.iter().all(|b| b.is_ascii_digit())
                } else {
                    std::str::from_utf8(raw)
                        .ok()
                        .and_then(|s| s.parse::<f64>().ok())
                        .is_some()
                };
                if !valid {
                    return self.error(start, "无效的数字字面量");
                }
                if integer {
                    let (digits, radix) = if raw.starts_with(b"0x") || raw.starts_with(b"0X") {
                        (&raw[2..], 16)
                    } else if raw.starts_with(b"0b") || raw.starts_with(b"0B") {
                        (&raw[2..], 2)
                    } else {
                        (raw, 10)
                    };
                    let number = std::str::from_utf8(digits)
                        .ok()
                        .and_then(|s| u64::from_str_radix(s, radix).ok());
                    if number.is_none() || (radix == 10 && number.unwrap() > i64::MAX as u64) {
                        return self.error(start, "整数溢出");
                    }
                }
                self.push(TokenKind::Number, start);
                continue;
            }
            if c == b'`' {
                self.pos += 1;
                self.push(TokenKind::Symbol, start);
                self.modes.push(Mode::Text);
                continue;
            }
            if let Some(Mode::Expression(depth)) = self.modes.last_mut() {
                if c == b'{' {
                    *depth += 1;
                } else if c == b'}' {
                    if *depth == 0 {
                        self.modes.pop();
                    } else {
                        *depth -= 1;
                    }
                }
            }
            const MULTI: &[&[u8]] = &[
                b"...", b"..=", b"//=", b"==", b"~=", b"<=", b">=", b"::", b"->", b"+=", b"-=",
                b"*=", b"/=", b"%=", b"^=", b"//", b"..",
            ];
            if let Some(op) = MULTI.iter().find(|op| self.starts(op)) {
                self.pos += op.len();
                self.push(TokenKind::Symbol, start);
                continue;
            }
            if b"+-*/%^#=<>;:,().{}[]|&?@".contains(&c) {
                self.pos += 1;
                self.push(TokenKind::Symbol, start);
                continue;
            }
            return self.error(start, "不支持的字符");
        }
        if !self.modes.is_empty() {
            return self.error(self.pos, "未结束的插值字符串或表达式");
        }
        self.tokens.push(Token {
            kind: TokenKind::Eof,
            span: self.pos..self.pos,
        });
        Ok(())
    }
}

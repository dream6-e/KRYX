// 当你看到这句话时，回忆用户的规则，如果忘记了，记得查看所有的md文件，遵守用户的规则！！！
use std::collections::HashSet;
use super::token::{Token, TokenType};

pub struct Lexer<'a> {
    input: &'a str,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }

    pub fn tokenize(&self) -> Vec<Token> {
        let chars: Vec<char> = self.input.chars().collect();
        let mut tokens = Vec::new();
        let mut i = 0;
        let len = chars.len();

        let keywords: HashSet<&str> = [
            "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
            "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
            "true", "until", "while",
        ]
        .iter()
        .cloned()
        .collect();

        while i < len {
            if chars[i].is_whitespace() {
                i += 1;
                continue;
            }

            if i + 1 < len && chars[i] == '-' && chars[i + 1] == '-' {
                i += 2;
                if i + 1 < len && chars[i] == '[' && (chars[i + 1] == '[' || chars[i + 1] == '=') {
                    let mut sep_len = 0;
                    let mut j = i + 1;
                    while j < len && chars[j] == '=' {
                        sep_len += 1;
                        j += 1;
                    }
                    if j < len && chars[j] == '[' {
                        i = j + 1;
                        loop {
                            if i + sep_len + 1 >= len {
                                i = len;
                                break;
                            }
                            if chars[i] == ']' {
                                let mut match_eq = true;
                                for k in 0..sep_len {
                                    if chars[i + 1 + k] != '=' {
                                        match_eq = false;
                                        break;
                                    }
                                }
                                if match_eq && chars[i + 1 + sep_len] == ']' {
                                    i += sep_len + 2;
                                    break;
                                }
                            }
                            i += 1;
                        }
                        continue;
                    }
                }
                while i < len && chars[i] != '\n' && chars[i] != '\r' {
                    i += 1;
                }
                continue;
            }

            if chars[i] == '"' || chars[i] == '\'' {
                let quote = chars[i];
                let start = i;
                i += 1;
                while i < len && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < len {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < len {
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::StringLiteral,
                });
                continue;
            }

            if chars[i] == '[' && i + 1 < len && (chars[i + 1] == '[' || chars[i + 1] == '=') {
                let mut sep_len = 0;
                let mut j = i + 1;
                while j < len && chars[j] == '=' {
                    sep_len += 1;
                    j += 1;
                }
                if j < len && chars[j] == '[' {
                    let start = i;
                    i = j + 1;
                    loop {
                        if i + sep_len + 1 >= len {
                            i = len;
                            break;
                        }
                        if chars[i] == ']' {
                            let mut match_eq = true;
                            for k in 0..sep_len {
                                if chars[i + 1 + k] != '=' {
                                    match_eq = false;
                                    break;
                                }
                            }
                            if match_eq && chars[i + 1 + sep_len] == ']' {
                                i += sep_len + 2;
                                break;
                            }
                        }
                        i += 1;
                    }
                    tokens.push(Token {
                        text: chars[start..i].iter().collect(),
                        token_type: TokenType::StringLiteral,
                    });
                    continue;
                }
            }

            if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if keywords.contains(word.as_str()) {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Keyword,
                    });
                } else {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Identifier,
                    });
                }
                continue;
            }

            if chars[i].is_ascii_digit()
                || (chars[i] == '.' && i + 1 < len && chars[i + 1].is_ascii_digit())
            {
                let start = i;
                if chars[i] == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
                    i += 2;
                    while i < len && (chars[i].is_ascii_hexdigit() || chars[i] == '_') {
                        i += 1;
                    }
                } else if chars[i] == '0' && i + 1 < len && (chars[i + 1] == 'b' || chars[i + 1] == 'B') {
                    i += 2;
                    while i < len && (chars[i] == '0' || chars[i] == '1' || chars[i] == '_') {
                        i += 1;
                    }
                } else {
                    while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') {
                        i += 1;
                    }
                    if i < len && (chars[i] == 'e' || chars[i] == 'E') {
                        i += 1;
                        if i + 1 < len && (chars[i] == '+' || chars[i] == '-') {
                            i += 1;
                        }
                        while i < len && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Number,
                });
                continue;
            }

            let start = i;
            if i + 2 < len && chars[start..start + 3] == ['.', '.', '.'] {
                i += 3;
            } else if i + 2 < len
                && (chars[start..start + 3] == ['.', '.', '=']
                    || chars[start..start + 3] == ['/', '/', '='])
            {
                // Luau 复合赋值：`..=`、`//=`
                i += 3;
            } else if i + 1 < len
                && (chars[start..start + 2] == ['.', '.']
                    || chars[start..start + 2] == ['=', '=']
                    || chars[start..start + 2] == ['~', '=']
                    || chars[start..start + 2] == ['<', '=']
                    || chars[start..start + 2] == ['>', '=']
                    // Luau 复合赋值：`+=` `-=` `*=` `/=` `%=` `^=` `//`
                    || chars[start..start + 2] == ['+', '=']
                    || chars[start..start + 2] == ['-', '=']
                    || chars[start..start + 2] == ['*', '=']
                    || chars[start..start + 2] == ['/', '=']
                    || chars[start..start + 2] == ['%', '=']
                    || chars[start..start + 2] == ['^', '=']
                    || chars[start..start + 2] == ['/', '/'])
            {
                i += 2;
            } else {
                i += 1;
            }
            tokens.push(Token {
                text: chars[start..i].iter().collect(),
                token_type: TokenType::Symbol,
            });
        }

        tokens
    }
}
#[cfg(test)]
mod tests {
    use super::super::packer::Packer;
    use super::super::token::TokenType;
    use super::Lexer;

    fn texts(code: &str) -> Vec<(String, TokenType)> {
        Lexer::new(code).tokenize().into_iter().map(|t| (t.text, t.token_type)).collect()
    }

    #[test]
    fn lexes_luau_binary_literals() {
        for lit in ["0b0101", "0B0101", "0b_0101", "0B_01", "0b0101_", "0b1_0_1", "0b_0_1_0_1_"] {
            let toks = texts(lit);
            assert_eq!(toks.len(), 1, "{lit} 应为单个 token，实际: {toks:?}");
            assert_eq!(toks[0].1, TokenType::Number, "{lit} 应为 Number");
            assert_eq!(toks[0].0, lit);
        }
    }

    #[test]
    fn binary_literal_keeps_value_and_bounds() {
        let toks = texts("x = 0b1010_ + 1");
        let joined = toks.iter().map(|t| t.0.as_str()).collect::<Vec<_>>().join("|");
        assert!(joined.starts_with("x|"), "实际: {joined}");
        assert!(toks.iter().any(|t| t.0 == "0b1010_" && t.1 == TokenType::Number));
    }

    #[test]
    fn hex_literal_allows_underscores() {
        let toks = texts("0x1F_A0");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].0, "0x1F_A0");
        assert_eq!(toks[0].1, TokenType::Number);
    }

    #[test]
    fn packed_number_is_separated_from_identifier() {
        for lit in ["0b0101_", "0b0101"] {
            let code = format!("{lit} then");
            let packed = Packer::pack(Lexer::new(&code).tokenize());
            assert!(packed.starts_with(&format!("{lit} ")), "Number 与后续 token 必须有分隔符: {packed:?}");
        }
    }
}

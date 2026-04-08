extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone, PartialEq)]
pub enum CssToken {
    Ident(String),
    Hash(String),
    String(String),
    Number(f32),
    Dimension(f32, String),
    Percentage(f32),
    Colon,
    Semicolon,
    Comma,
    OpenBrace,
    CloseBrace,
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    Dot,
    Greater,
    Plus,
    Tilde,
    Star,
    AtKeyword(String),
    Function(String),
    Whitespace,
    Delim(char),
}

impl CssToken {
    pub fn is_whitespace(&self) -> bool {
        matches!(self, CssToken::Whitespace)
    }

    pub fn as_ident(&self) -> Option<&str> {
        match self {
            CssToken::Ident(s) => Some(s),
            _ => None,
        }
    }
}

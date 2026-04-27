// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// AGPL-3.0-or-later

extern crate alloc;
use super::types::Token;
use alloc::string::String;
use alloc::vec::Vec;

pub fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\r' => {
                chars.next();
            }
            '\n' => {
                chars.next();
                tokens.push(Token::Newline);
            }
            '#' => {
                while chars.peek().map_or(false, |&c| c != '\n') {
                    chars.next();
                }
            }
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Eq);
                } else {
                    tokens.push(Token::Assign);
                }
            }
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Ne);
                } else {
                    tokens.push(Token::Not);
                }
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Le);
                } else {
                    tokens.push(Token::Lt);
                }
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Ge);
                } else {
                    tokens.push(Token::Gt);
                }
            }
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push(Token::And);
                } else {
                    tokens.push(Token::Amp);
                }
            }
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    tokens.push(Token::Or);
                } else {
                    tokens.push(Token::Pipe);
                }
            }
            ';' => {
                chars.next();
                tokens.push(Token::Semi);
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '{' => {
                chars.next();
                tokens.push(Token::LBrace);
            }
            '}' => {
                chars.next();
                tokens.push(Token::RBrace);
            }
            '[' => {
                chars.next();
                tokens.push(Token::LBracket);
            }
            ']' => {
                chars.next();
                tokens.push(Token::RBracket);
            }
            '$' => {
                chars.next();
                tokens.push(Token::Dollar);
            }
            ',' => {
                chars.next();
                tokens.push(Token::Comma);
            }
            '"' | '\'' => {
                let q = chars.next().unwrap();
                let s = scan_string(&mut chars, q);
                tokens.push(Token::Str(s));
            }
            '0'..='9' | '-'
                if c == '-' && chars.clone().nth(1).map_or(false, |n| n.is_ascii_digit()) =>
            {
                tokens.push(Token::Num(scan_number(&mut chars)));
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                let id = scan_ident(&mut chars);
                tokens.push(keyword_or_ident(id));
            }
            _ => {
                chars.next();
            }
        }
    }
    tokens.push(Token::Eof);
    tokens
}

fn scan_string(chars: &mut core::iter::Peekable<core::str::Chars>, quote: char) -> String {
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c == quote {
            chars.next();
            break;
        }
        if c == '\\' {
            chars.next();
            if let Some(&esc) = chars.peek() {
                chars.next();
                s.push(match esc {
                    'n' => '\n',
                    't' => '\t',
                    _ => esc,
                });
            }
        } else {
            s.push(chars.next().unwrap());
        }
    }
    s
}

fn scan_number(chars: &mut core::iter::Peekable<core::str::Chars>) -> i64 {
    let mut s = String::new();
    if chars.peek() == Some(&'-') {
        s.push(chars.next().unwrap());
    }
    while chars.peek().map_or(false, |c| c.is_ascii_digit()) {
        s.push(chars.next().unwrap());
    }
    s.parse().unwrap_or(0)
}

fn scan_ident(chars: &mut core::iter::Peekable<core::str::Chars>) -> String {
    let mut s = String::new();
    while chars.peek().map_or(false, |c| c.is_alphanumeric() || *c == '_') {
        s.push(chars.next().unwrap());
    }
    s
}

fn keyword_or_ident(s: String) -> Token {
    match s.as_str() {
        "if" => Token::If,
        "then" => Token::Then,
        "else" => Token::Else,
        "fi" => Token::Fi,
        "for" => Token::For,
        "in" => Token::In,
        "do" => Token::Do,
        "done" => Token::Done,
        "while" => Token::While,
        "fn" => Token::Fn,
        "return" => Token::Return,
        _ => Token::Ident(s),
    }
}

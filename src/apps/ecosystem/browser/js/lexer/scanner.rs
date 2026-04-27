// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::token::{Token, TokenKind};
use alloc::vec::Vec;

pub struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self { src, pos: 0, line: 1, col: 1 }
    }
    pub fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }
    pub fn peek_n(&self, n: usize) -> Option<char> {
        self.src[self.pos..].chars().nth(n)
    }
    pub fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }
    pub fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }
    pub fn skip_comment(&mut self) -> bool {
        if self.peek() == Some('/') && self.peek_n(1) == Some('/') {
            while let Some(c) = self.advance() {
                if c == '\n' {
                    break;
                }
            }
            return true;
        }
        if self.peek() == Some('/') && self.peek_n(1) == Some('*') {
            self.advance();
            self.advance();
            while let Some(c) = self.advance() {
                if c == '*' && self.peek() == Some('/') {
                    self.advance();
                    break;
                }
            }
            return true;
        }
        false
    }
    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        loop {
            self.skip_ws();
            while self.skip_comment() {
                self.skip_ws();
            }
            let (line, col) = (self.line, self.col);
            let kind = self.scan_token();
            tokens.push(Token { kind: kind.clone(), line, col });
            if kind == TokenKind::Eof {
                break;
            }
        }
        tokens
    }
    fn scan_token(&mut self) -> TokenKind {
        let c = match self.peek() {
            Some(c) => c,
            None => return TokenKind::Eof,
        };
        if c.is_ascii_digit()
            || (c == '.' && self.peek_n(1).map(|c| c.is_ascii_digit()).unwrap_or(false))
        {
            return self.scan_number();
        }
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            return self.scan_ident();
        }
        if c == '"' || c == '\'' || c == '`' {
            return self.scan_string();
        }
        self.scan_punct()
    }
}

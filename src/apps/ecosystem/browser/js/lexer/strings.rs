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
use super::scanner::Lexer;
use super::token::TokenKind;
use alloc::string::String;

impl<'a> Lexer<'a> {
    pub fn scan_string(&mut self) -> TokenKind {
        let Some(quote) = self.advance() else {
            return TokenKind::Invalid;
        };
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c == quote {
                self.advance();
                break;
            }
            if c == '\\' {
                self.advance();
                match self.peek() {
                    Some('n') => {
                        self.advance();
                        s.push('\n');
                    }
                    Some('r') => {
                        self.advance();
                        s.push('\r');
                    }
                    Some('t') => {
                        self.advance();
                        s.push('\t');
                    }
                    Some('\\') => {
                        self.advance();
                        s.push('\\');
                    }
                    Some('\'') => {
                        self.advance();
                        s.push('\'');
                    }
                    Some('"') => {
                        self.advance();
                        s.push('"');
                    }
                    Some('`') => {
                        self.advance();
                        s.push('`');
                    }
                    Some('0') => {
                        self.advance();
                        s.push('\0');
                    }
                    Some('x') => {
                        self.advance();
                        s.push(self.scan_hex_escape(2));
                    }
                    Some('u') => {
                        self.advance();
                        s.push(self.scan_unicode_escape());
                    }
                    Some(c) => {
                        self.advance();
                        s.push(c);
                    }
                    None => break,
                }
            } else if let Some(ch) = self.advance() {
                s.push(ch);
            } else {
                break;
            }
        }
        TokenKind::String(s)
    }
    fn scan_hex_escape(&mut self, len: usize) -> char {
        let mut val = 0u32;
        for _ in 0..len {
            if let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    val = val * 16 + c.to_digit(16).unwrap_or(0);
                    self.advance();
                } else {
                    break;
                }
            }
        }
        char::from_u32(val).unwrap_or('\u{FFFD}')
    }
    fn scan_unicode_escape(&mut self) -> char {
        if self.peek() == Some('{') {
            self.advance();
            let mut val = 0u32;
            while let Some(c) = self.peek() {
                if c == '}' {
                    self.advance();
                    break;
                }
                if c.is_ascii_hexdigit() {
                    val = val * 16 + c.to_digit(16).unwrap_or(0);
                    self.advance();
                } else {
                    break;
                }
            }
            char::from_u32(val).unwrap_or('\u{FFFD}')
        } else {
            self.scan_hex_escape(4)
        }
    }
}

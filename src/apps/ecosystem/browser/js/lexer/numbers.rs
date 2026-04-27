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
    pub fn scan_number(&mut self) -> TokenKind {
        let mut s = String::new();
        if self.peek() == Some('0') && matches!(self.peek_n(1), Some('x') | Some('X')) {
            if let Some(c) = self.advance() {
                s.push(c);
            }
            if let Some(c) = self.advance() {
                s.push(c);
            }
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    if let Some(ch) = self.advance() {
                        s.push(ch);
                    }
                } else {
                    break;
                }
            }
            return TokenKind::Number(
                i64::from_str_radix(s.get(2..).unwrap_or("0"), 16).unwrap_or(0) as f64,
            );
        }
        if self.peek() == Some('0') && matches!(self.peek_n(1), Some('b') | Some('B')) {
            if let Some(c) = self.advance() {
                s.push(c);
            }
            if let Some(c) = self.advance() {
                s.push(c);
            }
            while let Some(c) = self.peek() {
                if c == '0' || c == '1' {
                    if let Some(ch) = self.advance() {
                        s.push(ch);
                    }
                } else {
                    break;
                }
            }
            return TokenKind::Number(
                i64::from_str_radix(s.get(2..).unwrap_or("0"), 2).unwrap_or(0) as f64,
            );
        }
        if self.peek() == Some('0') && matches!(self.peek_n(1), Some('o') | Some('O')) {
            if let Some(c) = self.advance() {
                s.push(c);
            }
            if let Some(c) = self.advance() {
                s.push(c);
            }
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() && c < '8' {
                    if let Some(ch) = self.advance() {
                        s.push(ch);
                    }
                } else {
                    break;
                }
            }
            return TokenKind::Number(
                i64::from_str_radix(s.get(2..).unwrap_or("0"), 8).unwrap_or(0) as f64,
            );
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                if let Some(ch) = self.advance() {
                    s.push(ch);
                }
            } else {
                break;
            }
        }
        if self.peek() == Some('.') && self.peek_n(1).map(|c| c.is_ascii_digit()).unwrap_or(false) {
            if let Some(c) = self.advance() {
                s.push(c);
            }
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    if let Some(ch) = self.advance() {
                        s.push(ch);
                    }
                } else {
                    break;
                }
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            if let Some(c) = self.advance() {
                s.push(c);
            }
            if matches!(self.peek(), Some('+') | Some('-')) {
                if let Some(c) = self.advance() {
                    s.push(c);
                }
            }
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    if let Some(ch) = self.advance() {
                        s.push(ch);
                    }
                } else {
                    break;
                }
            }
        }
        TokenKind::Number(s.parse().unwrap_or(0.0))
    }
}

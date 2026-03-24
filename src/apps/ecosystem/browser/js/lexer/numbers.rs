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
use alloc::string::String;
use super::scanner::Lexer;
use super::token::TokenKind;

impl<'a> Lexer<'a> {
    pub fn scan_number(&mut self) -> TokenKind {
        let mut s = String::new();
        if self.peek() == Some('0') && matches!(self.peek_n(1), Some('x') | Some('X')) {
            s.push(self.advance().unwrap()); s.push(self.advance().unwrap());
            while let Some(c) = self.peek() { if c.is_ascii_hexdigit() { s.push(self.advance().unwrap()); } else { break; } }
            return TokenKind::Number(i64::from_str_radix(&s[2..], 16).unwrap_or(0) as f64);
        }
        if self.peek() == Some('0') && matches!(self.peek_n(1), Some('b') | Some('B')) {
            s.push(self.advance().unwrap()); s.push(self.advance().unwrap());
            while let Some(c) = self.peek() { if c == '0' || c == '1' { s.push(self.advance().unwrap()); } else { break; } }
            return TokenKind::Number(i64::from_str_radix(&s[2..], 2).unwrap_or(0) as f64);
        }
        if self.peek() == Some('0') && matches!(self.peek_n(1), Some('o') | Some('O')) {
            s.push(self.advance().unwrap()); s.push(self.advance().unwrap());
            while let Some(c) = self.peek() { if c.is_ascii_digit() && c < '8' { s.push(self.advance().unwrap()); } else { break; } }
            return TokenKind::Number(i64::from_str_radix(&s[2..], 8).unwrap_or(0) as f64);
        }
        while let Some(c) = self.peek() { if c.is_ascii_digit() { s.push(self.advance().unwrap()); } else { break; } }
        if self.peek() == Some('.') && self.peek_n(1).map(|c| c.is_ascii_digit()).unwrap_or(false) {
            s.push(self.advance().unwrap());
            while let Some(c) = self.peek() { if c.is_ascii_digit() { s.push(self.advance().unwrap()); } else { break; } }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            s.push(self.advance().unwrap());
            if matches!(self.peek(), Some('+') | Some('-')) { s.push(self.advance().unwrap()); }
            while let Some(c) = self.peek() { if c.is_ascii_digit() { s.push(self.advance().unwrap()); } else { break; } }
        }
        TokenKind::Number(s.parse().unwrap_or(0.0))
    }
}

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
use super::keywords::lookup_keyword;
use super::scanner::Lexer;
use super::token::TokenKind;
use alloc::string::String;

impl<'a> Lexer<'a> {
    pub fn scan_ident(&mut self) -> TokenKind {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                if let Some(ch) = self.advance() {
                    s.push(ch);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        lookup_keyword(&s).unwrap_or(TokenKind::Identifier(s))
    }
}

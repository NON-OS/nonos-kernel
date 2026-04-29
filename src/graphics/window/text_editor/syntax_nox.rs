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

use super::syntax::TokenType;

const KW: &[&[u8]] = &[
    b"let",
    b"fn",
    b"if",
    b"else",
    b"while",
    b"for",
    b"return",
    b"print",
    b"true",
    b"false",
    b"nil",
    b"and",
    b"or",
    b"not",
    b"in",
    b"break",
    b"continue",
];

pub(super) fn tokenize(line: &[u8]) -> alloc::vec::Vec<(u8, TokenType)> {
    let mut r = alloc::vec::Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if line[i] == b'#' {
            while i < line.len() {
                r.push((line[i], TokenType::Comment));
                i += 1;
            }
        } else if line[i] == b'"' {
            r.push((line[i], TokenType::String));
            i += 1;
            while i < line.len() && line[i] != b'"' {
                r.push((line[i], TokenType::String));
                i += 1;
            }
            if i < line.len() {
                r.push((line[i], TokenType::String));
                i += 1;
            }
        } else if line[i].is_ascii_digit() {
            while i < line.len()
                && (line[i].is_ascii_alphanumeric() || line[i] == b'.' || line[i] == b'_')
            {
                r.push((line[i], TokenType::Number));
                i += 1;
            }
        } else if line[i].is_ascii_alphabetic() || line[i] == b'_' {
            let s = i;
            while i < line.len() && (line[i].is_ascii_alphanumeric() || line[i] == b'_') {
                i += 1;
            }
            let w = &line[s..i];
            let t = if KW.iter().any(|k| *k == w) {
                TokenType::Keyword
            } else if i < line.len() && line[i] == b'(' {
                TokenType::Function
            } else {
                TokenType::Default
            };
            for &b in w {
                r.push((b, t));
            }
        } else {
            r.push((line[i], TokenType::Default));
            i += 1;
        }
    }
    r
}

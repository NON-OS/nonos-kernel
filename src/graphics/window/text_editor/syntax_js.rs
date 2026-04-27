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

use super::syntax::TokenType;

const KW: &[&[u8]] = &[
    b"function",
    b"const",
    b"let",
    b"var",
    b"if",
    b"else",
    b"for",
    b"while",
    b"do",
    b"switch",
    b"case",
    b"break",
    b"continue",
    b"return",
    b"throw",
    b"try",
    b"catch",
    b"finally",
    b"new",
    b"delete",
    b"typeof",
    b"instanceof",
    b"in",
    b"of",
    b"class",
    b"extends",
    b"super",
    b"this",
    b"import",
    b"export",
    b"default",
    b"from",
    b"as",
    b"async",
    b"await",
    b"yield",
    b"true",
    b"false",
    b"null",
    b"undefined",
];
const TY: &[&[u8]] = &[
    b"string",
    b"number",
    b"boolean",
    b"object",
    b"any",
    b"void",
    b"never",
    b"unknown",
    b"Array",
    b"Object",
    b"String",
    b"Number",
    b"Boolean",
    b"Promise",
    b"Map",
    b"Set",
    b"Date",
    b"RegExp",
    b"Error",
    b"Function",
];

pub(super) fn tokenize(line: &[u8]) -> alloc::vec::Vec<(u8, TokenType)> {
    let mut r = alloc::vec::Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if line[i..].starts_with(b"//") {
            while i < line.len() {
                r.push((line[i], TokenType::Comment));
                i += 1;
            }
        } else if line[i] == b'"' || line[i] == b'\'' || line[i] == b'`' {
            let q = line[i];
            r.push((line[i], TokenType::String));
            i += 1;
            while i < line.len() {
                r.push((line[i], TokenType::String));
                if line[i] == b'\\' && i + 1 < line.len() {
                    i += 1;
                    r.push((line[i], TokenType::String));
                } else if line[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else if line[i].is_ascii_digit() {
            while i < line.len()
                && (line[i].is_ascii_alphanumeric() || line[i] == b'_' || line[i] == b'.')
            {
                r.push((line[i], TokenType::Number));
                i += 1;
            }
        } else if line[i].is_ascii_alphabetic() || line[i] == b'_' || line[i] == b'$' {
            let s = i;
            while i < line.len()
                && (line[i].is_ascii_alphanumeric() || line[i] == b'_' || line[i] == b'$')
            {
                i += 1;
            }
            let w = &line[s..i];
            let t = if KW.iter().any(|k| *k == w) {
                TokenType::Keyword
            } else if TY.iter().any(|t| *t == w) {
                TokenType::Type
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

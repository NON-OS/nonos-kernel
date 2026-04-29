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
    b"def",
    b"class",
    b"if",
    b"elif",
    b"else",
    b"for",
    b"while",
    b"try",
    b"except",
    b"finally",
    b"with",
    b"as",
    b"import",
    b"from",
    b"return",
    b"yield",
    b"raise",
    b"pass",
    b"break",
    b"continue",
    b"and",
    b"or",
    b"not",
    b"in",
    b"is",
    b"lambda",
    b"global",
    b"nonlocal",
    b"assert",
    b"del",
    b"True",
    b"False",
    b"None",
    b"async",
    b"await",
];
const TY: &[&[u8]] = &[
    b"int",
    b"float",
    b"str",
    b"bool",
    b"list",
    b"dict",
    b"set",
    b"tuple",
    b"bytes",
    b"bytearray",
    b"object",
    b"type",
    b"List",
    b"Dict",
    b"Set",
    b"Tuple",
    b"Optional",
    b"Union",
    b"Any",
    b"Callable",
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
        } else if line[i] == b'"' || line[i] == b'\'' {
            let q = line[i];
            let triple = i + 2 < line.len() && line[i + 1] == q && line[i + 2] == q;
            if triple {
                for _ in 0..3 {
                    r.push((line[i], TokenType::String));
                    i += 1;
                }
            } else {
                r.push((line[i], TokenType::String));
                i += 1;
            }
            while i < line.len() {
                if triple
                    && i + 2 < line.len()
                    && line[i] == q
                    && line[i + 1] == q
                    && line[i + 2] == q
                {
                    for _ in 0..3 {
                        r.push((line[i], TokenType::String));
                        i += 1;
                    }
                    break;
                } else if !triple && line[i] == q {
                    r.push((line[i], TokenType::String));
                    i += 1;
                    break;
                }
                r.push((line[i], TokenType::String));
                if line[i] == b'\\' && i + 1 < line.len() {
                    i += 1;
                    r.push((line[i], TokenType::String));
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
        } else if line[i].is_ascii_alphabetic() || line[i] == b'_' {
            let s = i;
            while i < line.len() && (line[i].is_ascii_alphanumeric() || line[i] == b'_') {
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

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
    b"goto",
    b"struct",
    b"union",
    b"enum",
    b"typedef",
    b"sizeof",
    b"static",
    b"extern",
    b"const",
    b"volatile",
    b"register",
    b"auto",
    b"inline",
    b"restrict",
    b"class",
    b"public",
    b"private",
    b"protected",
    b"virtual",
    b"override",
    b"final",
    b"new",
    b"delete",
    b"try",
    b"catch",
    b"throw",
    b"namespace",
    b"using",
    b"template",
    b"typename",
    b"nullptr",
    b"true",
    b"false",
];
const TY: &[&[u8]] = &[
    b"void",
    b"char",
    b"short",
    b"int",
    b"long",
    b"float",
    b"double",
    b"signed",
    b"unsigned",
    b"bool",
    b"size_t",
    b"ssize_t",
    b"uint8_t",
    b"uint16_t",
    b"uint32_t",
    b"uint64_t",
    b"int8_t",
    b"int16_t",
    b"int32_t",
    b"int64_t",
    b"uintptr_t",
    b"intptr_t",
    b"FILE",
    b"NULL",
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
        } else if line[i] == b'#' {
            while i < line.len() {
                r.push((line[i], TokenType::Keyword));
                i += 1;
            }
        } else if line[i] == b'"' || line[i] == b'\'' {
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
                && (line[i].is_ascii_alphanumeric()
                    || line[i] == b'_'
                    || line[i] == b'.'
                    || line[i] == b'x'
                    || line[i] == b'X')
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

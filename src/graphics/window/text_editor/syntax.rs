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

use core::sync::atomic::{AtomicU8, Ordering};

pub const KEYWORD: u32 = 0xFFFF7B72;
pub const STRING: u32 = 0xFFA5D6FF;
pub const COMMENT: u32 = 0xFF8B949E;
pub const NUMBER: u32 = 0xFF79C0FF;
pub const FUNCTION: u32 = 0xFFD2A8FF;
pub const TYPE: u32 = 0xFF7EE787;
pub const DEFAULT: u32 = 0xFFE6EDF3;

#[derive(Clone, Copy, PartialEq)]
pub enum TokenType {
    Default,
    Keyword,
    String,
    Comment,
    Number,
    Function,
    Type,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Language {
    Plain,
    Rust,
    JavaScript,
    Python,
    C,
    Nox,
}

pub(crate) static CURRENT_LANG: AtomicU8 = AtomicU8::new(0);

pub fn detect_language(path: &[u8]) -> Language {
    if path.ends_with(b".rs") {
        Language::Rust
    } else if path.ends_with(b".js")
        || path.ends_with(b".ts")
        || path.ends_with(b".jsx")
        || path.ends_with(b".tsx")
    {
        Language::JavaScript
    } else if path.ends_with(b".py") {
        Language::Python
    } else if path.ends_with(b".c")
        || path.ends_with(b".h")
        || path.ends_with(b".cpp")
        || path.ends_with(b".hpp")
    {
        Language::C
    } else if path.ends_with(b".nox") {
        Language::Nox
    } else {
        Language::Plain
    }
}

pub fn set_language(lang: Language) {
    CURRENT_LANG.store(lang as u8, Ordering::Relaxed);
}
pub fn get_language() -> Language {
    match CURRENT_LANG.load(Ordering::Relaxed) {
        1 => Language::Rust,
        2 => Language::JavaScript,
        3 => Language::Python,
        4 => Language::C,
        5 => Language::Nox,
        _ => Language::Plain,
    }
}

pub fn tokenize_line(line: &[u8]) -> alloc::vec::Vec<(u8, TokenType)> {
    match get_language() {
        Language::Rust => super::syntax_rust::tokenize(line),
        Language::JavaScript => super::syntax_js::tokenize(line),
        Language::Python => super::syntax_py::tokenize(line),
        Language::C => super::syntax_c::tokenize(line),
        Language::Nox => super::syntax_nox::tokenize(line),
        Language::Plain => line.iter().map(|&b| (b, TokenType::Default)).collect(),
    }
}

pub fn token_color(tt: TokenType) -> u32 {
    match tt {
        TokenType::Keyword => KEYWORD,
        TokenType::String => STRING,
        TokenType::Comment => COMMENT,
        TokenType::Number => NUMBER,
        TokenType::Function => FUNCTION,
        TokenType::Type => TYPE,
        TokenType::Default => DEFAULT,
    }
}

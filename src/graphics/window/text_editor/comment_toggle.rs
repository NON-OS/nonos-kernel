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

use super::comment_apply::{add_comment, remove_comment};
use super::state::*;
use super::syntax::{Language, CURRENT_LANG};
use core::sync::atomic::Ordering;

pub fn toggle_comment() -> bool {
    let lang = CURRENT_LANG.load(Ordering::Relaxed);
    let prefix = get_comment_prefix(lang);
    if prefix.is_empty() {
        return false;
    }
    let (line_start, _) = get_current_line_bounds();
    if is_line_commented(line_start, prefix) {
        remove_comment(line_start, prefix)
    } else {
        add_comment(line_start, prefix)
    }
}

fn get_comment_prefix(lang: u8) -> &'static [u8] {
    match lang {
        l if l == Language::Rust as u8 => b"// ",
        l if l == Language::JavaScript as u8 => b"// ",
        l if l == Language::Python as u8 => b"# ",
        l if l == Language::C as u8 => b"// ",
        l if l == Language::Nox as u8 => b"# ",
        _ => b"",
    }
}

pub(super) fn get_current_line_bounds() -> (usize, usize) {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let mut start = cursor;
    while start > 0 && unsafe { EDITOR_BUFFER[start - 1] } != b'\n' {
        start -= 1;
    }
    let mut end = cursor;
    while end < len && unsafe { EDITOR_BUFFER[end] } != b'\n' {
        end += 1;
    }
    (start, end)
}

fn is_line_commented(start: usize, prefix: &[u8]) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let mut pos = start;
    while pos < len && unsafe { EDITOR_BUFFER[pos] } == b' ' {
        pos += 1;
    }
    for (i, &ch) in prefix.iter().enumerate() {
        if pos + i >= len || unsafe { EDITOR_BUFFER[pos + i] } != ch {
            return false;
        }
    }
    true
}

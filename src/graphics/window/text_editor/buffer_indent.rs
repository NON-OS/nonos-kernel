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

use super::buffer_insert::insert_str;
use super::state::*;
use core::sync::atomic::Ordering;

pub(super) fn insert_newline_with_indent() -> bool {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let indent = get_current_line_indent(cursor);
    let extra = check_open_brace(cursor);
    let mut buf = [0u8; 65];
    buf[0] = b'\n';
    let mut len = 1;
    for _ in 0..indent.min(32) {
        buf[len] = b' ';
        len += 1;
    }
    if extra {
        for _ in 0..4 {
            buf[len] = b' ';
            len += 1;
        }
    }
    insert_str(&buf[..len])
}

fn get_current_line_indent(cursor: usize) -> usize {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor == 0 || len == 0 {
        return 0;
    }
    let mut line_start = cursor;
    while line_start > 0 {
        if unsafe { EDITOR_BUFFER[line_start - 1] } == b'\n' {
            break;
        }
        line_start -= 1;
    }
    let mut indent = 0;
    let mut pos = line_start;
    while pos < cursor && pos < len {
        let ch = unsafe { EDITOR_BUFFER[pos] };
        if ch == b' ' {
            indent += 1;
        } else if ch == b'\t' {
            indent += 4;
        } else {
            break;
        }
        pos += 1;
    }
    indent
}

fn check_open_brace(cursor: usize) -> bool {
    if cursor == 0 {
        return false;
    }
    let mut pos = cursor - 1;
    while pos > 0 {
        let ch = unsafe { EDITOR_BUFFER[pos] };
        if ch == b'\n' {
            return false;
        }
        if ch == b'{' || ch == b'(' || ch == b'[' {
            return true;
        }
        if ch != b' ' && ch != b'\t' {
            return false;
        }
        pos -= 1;
    }
    false
}

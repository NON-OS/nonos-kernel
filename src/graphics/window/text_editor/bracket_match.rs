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

use super::state::*;
use core::sync::atomic::Ordering;

pub fn find_matching_bracket() -> Option<usize> {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor >= len {
        return None;
    }
    let ch = unsafe { EDITOR_BUFFER[cursor] };
    match ch {
        b'(' => find_forward(cursor, len, b'(', b')'),
        b'{' => find_forward(cursor, len, b'{', b'}'),
        b'[' => find_forward(cursor, len, b'[', b']'),
        b')' => find_backward(cursor, b'(', b')'),
        b'}' => find_backward(cursor, b'{', b'}'),
        b']' => find_backward(cursor, b'[', b']'),
        _ => None,
    }
}

fn find_forward(cursor: usize, len: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0;
    for i in cursor..len {
        let ch = unsafe { EDITOR_BUFFER[i] };
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn find_backward(cursor: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0;
    let mut i = cursor;
    loop {
        let ch = unsafe { EDITOR_BUFFER[i] };
        if ch == close {
            depth += 1;
        } else if ch == open {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

pub fn get_bracket_at_cursor() -> Option<u8> {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor >= len {
        return None;
    }
    let ch = unsafe { EDITOR_BUFFER[cursor] };
    if matches!(ch, b'(' | b')' | b'{' | b'}' | b'[' | b']') {
        Some(ch)
    } else {
        None
    }
}

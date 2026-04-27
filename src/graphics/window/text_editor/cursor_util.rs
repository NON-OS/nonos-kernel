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

pub(super) fn get_line_col() -> (usize, usize) {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return (1, 1);
    }
    let mut line = 1usize;
    let mut col = 1usize;
    unsafe {
        for i in 0..cursor.min(len) {
            if EDITOR_BUFFER[i] == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
    }
    (line, col)
}

pub(super) fn ensure_visible(max_lines: usize) {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let scroll_y = EDITOR_SCROLL_Y.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let mut cursor_line = 0usize;
    unsafe {
        for i in 0..cursor.min(len) {
            if EDITOR_BUFFER[i] == b'\n' {
                cursor_line += 1;
            }
        }
    }
    if cursor_line < scroll_y {
        EDITOR_SCROLL_Y.store(cursor_line, Ordering::Relaxed);
    } else if cursor_line >= scroll_y + max_lines {
        EDITOR_SCROLL_Y.store(cursor_line - max_lines + 1, Ordering::Relaxed);
    }
}

pub(super) fn goto_line(line_num: usize) {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if line_num == 0 {
        return;
    }
    let target = line_num - 1;
    let mut current_line = 0usize;
    let mut pos = 0usize;
    unsafe {
        while pos < len && current_line < target {
            if EDITOR_BUFFER[pos] == b'\n' {
                current_line += 1;
            }
            pos += 1;
        }
    }
    EDITOR_CURSOR.store(pos, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    ensure_visible(20);
}

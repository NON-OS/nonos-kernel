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

use core::sync::atomic::Ordering;
use super::state::*;

pub(super) fn move_left() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    if cursor > 0 {
        EDITOR_CURSOR.store(cursor - 1, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_right() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor < len {
        EDITOR_CURSOR.store(cursor + 1, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_up() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor == 0 || len == 0 {
        return;
    }

    unsafe {
        let mut line_start = cursor;
        while line_start > 0 && EDITOR_BUFFER[line_start - 1] != b'\n' {
            line_start -= 1;
        }
        let col = cursor - line_start;

        if line_start == 0 {
            return;
        }

        let prev_line_end = line_start - 1;
        let mut prev_line_start = prev_line_end;
        while prev_line_start > 0 && EDITOR_BUFFER[prev_line_start - 1] != b'\n' {
            prev_line_start -= 1;
        }
        let prev_line_len = prev_line_end - prev_line_start;

        let new_cursor = prev_line_start + col.min(prev_line_len);
        EDITOR_CURSOR.store(new_cursor, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_down() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return;
    }

    unsafe {
        let mut line_start = cursor;
        while line_start > 0 && EDITOR_BUFFER[line_start - 1] != b'\n' {
            line_start -= 1;
        }
        let col = cursor - line_start;

        let mut next_line_start = cursor;
        while next_line_start < len && EDITOR_BUFFER[next_line_start] != b'\n' {
            next_line_start += 1;
        }

        if next_line_start >= len {
            return;
        }

        next_line_start += 1;

        let mut next_line_end = next_line_start;
        while next_line_end < len && EDITOR_BUFFER[next_line_end] != b'\n' {
            next_line_end += 1;
        }
        let next_line_len = next_line_end - next_line_start;

        let new_cursor = next_line_start + col.min(next_line_len);
        EDITOR_CURSOR.store(new_cursor, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_to_line_start() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    unsafe {
        let mut line_start = cursor;
        while line_start > 0 && EDITOR_BUFFER[line_start - 1] != b'\n' {
            line_start -= 1;
        }
        EDITOR_CURSOR.store(line_start, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_to_line_end() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    unsafe {
        let mut line_end = cursor;
        while line_end < len && EDITOR_BUFFER[line_end] != b'\n' {
            line_end += 1;
        }
        EDITOR_CURSOR.store(line_end, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_to_start() {
    EDITOR_CURSOR.store(0, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn move_to_end() {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    EDITOR_CURSOR.store(len, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn move_word_left() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    if cursor == 0 {
        return;
    }

    unsafe {
        let mut pos = cursor - 1;
        while pos > 0 && EDITOR_BUFFER[pos] == b' ' {
            pos -= 1;
        }
        while pos > 0 && EDITOR_BUFFER[pos - 1] != b' ' && EDITOR_BUFFER[pos - 1] != b'\n' {
            pos -= 1;
        }
        EDITOR_CURSOR.store(pos, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn move_word_right() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor >= len {
        return;
    }

    unsafe {
        let mut pos = cursor;
        while pos < len && EDITOR_BUFFER[pos] != b' ' && EDITOR_BUFFER[pos] != b'\n' {
            pos += 1;
        }
        while pos < len && EDITOR_BUFFER[pos] == b' ' {
            pos += 1;
        }
        EDITOR_CURSOR.store(pos, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    }
}

pub(super) fn set_position(pos: usize) {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    EDITOR_CURSOR.store(pos.min(len), Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

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

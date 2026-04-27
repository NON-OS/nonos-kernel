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

pub(super) fn move_to_start() {
    EDITOR_CURSOR.store(0, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn move_to_end() {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    EDITOR_CURSOR.store(len, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn set_position(pos: usize) {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    EDITOR_CURSOR.store(pos.min(len), Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn get_line_start(cursor: usize) -> usize {
    let mut start = cursor;
    unsafe {
        while start > 0 && EDITOR_BUFFER[start - 1] != b'\n' {
            start -= 1;
        }
    }
    start
}

pub(super) fn get_line_end(cursor: usize, len: usize) -> usize {
    let mut end = cursor;
    unsafe {
        while end < len && EDITOR_BUFFER[end] != b'\n' {
            end += 1;
        }
    }
    end
}

pub(super) use super::cursor_line::{move_down, move_to_line_end, move_to_line_start, move_up};
pub(super) use super::cursor_util::{ensure_visible, get_line_col, goto_line};
pub(super) use super::cursor_word::{move_word_left, move_word_right};

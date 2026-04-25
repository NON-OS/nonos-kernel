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

use super::cursor::{get_line_end, get_line_start};
use super::state::*;
use core::sync::atomic::Ordering;

pub(super) fn move_up() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if cursor == 0 || len == 0 {
        return;
    }
    let line_start = get_line_start(cursor);
    let col = cursor - line_start;
    if line_start == 0 {
        return;
    }
    let prev_line_end = line_start - 1;
    let prev_line_start = get_line_start(prev_line_end);
    let prev_line_len = prev_line_end - prev_line_start;
    let new_cursor = prev_line_start + col.min(prev_line_len);
    EDITOR_CURSOR.store(new_cursor, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn move_down() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return;
    }
    let line_start = get_line_start(cursor);
    let col = cursor - line_start;
    let line_end = get_line_end(cursor, len);
    if line_end >= len {
        return;
    }
    let next_line_start = line_end + 1;
    let next_line_end = get_line_end(next_line_start, len);
    let next_line_len = next_line_end - next_line_start;
    let new_cursor = next_line_start + col.min(next_line_len);
    EDITOR_CURSOR.store(new_cursor, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn move_to_line_start() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let start = get_line_start(cursor);
    EDITOR_CURSOR.store(start, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn move_to_line_end() {
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let end = get_line_end(cursor, len);
    EDITOR_CURSOR.store(end, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

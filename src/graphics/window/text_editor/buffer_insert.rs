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

use super::buffer_undo::push_undo;
use super::state::*;
use core::sync::atomic::Ordering;

pub(super) fn insert_char(ch: u8) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    if len >= BUFFER_SIZE - 1 {
        return false;
    }
    push_undo(UndoOpType::Insert, cursor, &[ch]);
    unsafe {
        for i in (cursor..len).rev() {
            EDITOR_BUFFER[i + 1] = EDITOR_BUFFER[i];
        }
        EDITOR_BUFFER[cursor] = ch;
    }
    EDITOR_LEN.store(len + 1, Ordering::Relaxed);
    EDITOR_CURSOR.store(cursor + 1, Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
}

pub(super) fn insert_str(s: &[u8]) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    if len + s.len() >= BUFFER_SIZE {
        return false;
    }
    if s.len() <= UNDO_DATA_SIZE {
        push_undo(UndoOpType::Insert, cursor, s);
    }
    unsafe {
        for i in (cursor..len).rev() {
            EDITOR_BUFFER[i + s.len()] = EDITOR_BUFFER[i];
        }
        for (i, &byte) in s.iter().enumerate() {
            EDITOR_BUFFER[cursor + i] = byte;
        }
    }
    EDITOR_LEN.store(len + s.len(), Ordering::Relaxed);
    EDITOR_CURSOR.store(cursor + s.len(), Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
}

pub(super) fn insert_tab() -> bool {
    insert_str(b"    ")
}

pub(super) fn insert_newline() -> bool {
    super::buffer_indent::insert_newline_with_indent()
}

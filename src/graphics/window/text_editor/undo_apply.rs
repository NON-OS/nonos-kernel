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
use super::undo_stack::{pop_undo, push_redo};
use core::sync::atomic::Ordering;

pub(super) fn undo() -> bool {
    let entry = match pop_undo() {
        Some(e) => e,
        None => return false,
    };
    match entry.op_type {
        UndoOpType::Insert => {
            if !undo_insert(&entry) {
                return false;
            }
            push_redo(entry);
        }
        UndoOpType::Delete => {
            if !undo_delete(&entry) {
                return false;
            }
            push_redo(entry);
        }
        UndoOpType::None => return false,
    }
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    true
}

fn undo_insert(entry: &UndoEntry) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let (start, del_len) = (entry.cursor_pos, entry.data_len);
    if start + del_len > len {
        return false;
    }
    unsafe {
        for i in start..len - del_len {
            EDITOR_BUFFER[i] = EDITOR_BUFFER[i + del_len];
        }
        for i in len - del_len..len {
            EDITOR_BUFFER[i] = 0;
        }
    }
    EDITOR_LEN.store(len - del_len, Ordering::Relaxed);
    EDITOR_CURSOR.store(start, Ordering::Relaxed);
    true
}

fn undo_delete(entry: &UndoEntry) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let (pos, ins_len) = (entry.cursor_pos, entry.data_len);
    if len + ins_len >= BUFFER_SIZE {
        return false;
    }
    unsafe {
        for i in (pos..len).rev() {
            EDITOR_BUFFER[i + ins_len] = EDITOR_BUFFER[i];
        }
        for i in 0..ins_len {
            EDITOR_BUFFER[pos + i] = entry.data[i];
        }
    }
    EDITOR_LEN.store(len + ins_len, Ordering::Relaxed);
    EDITOR_CURSOR.store(pos + ins_len, Ordering::Relaxed);
    true
}

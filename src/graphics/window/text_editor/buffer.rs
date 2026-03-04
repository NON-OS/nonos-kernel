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
use super::buffer_undo::push_undo;

pub(super) use super::buffer_undo::{undo, redo};
pub(super) use super::buffer_clipboard::{copy_selection, cut_selection, paste};

pub(super) fn insert_char(ch: u8) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);

    if len >= BUFFER_SIZE - 1 {
        return false;
    }

    push_undo(UndoOpType::Insert, cursor, &[ch]);

    // SAFETY: Single-threaded buffer access
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

    // SAFETY: Single-threaded buffer access
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

pub(super) fn delete_backward() -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);

    if cursor == 0 || len == 0 {
        return false;
    }

    // SAFETY: Single-threaded buffer access
    let deleted_char = unsafe { EDITOR_BUFFER[cursor - 1] };
    push_undo(UndoOpType::Delete, cursor - 1, &[deleted_char]);

    // SAFETY: Single-threaded buffer access
    unsafe {
        for i in cursor..len {
            EDITOR_BUFFER[i - 1] = EDITOR_BUFFER[i];
        }
        EDITOR_BUFFER[len - 1] = 0;
    }

    EDITOR_LEN.store(len - 1, Ordering::Relaxed);
    EDITOR_CURSOR.store(cursor - 1, Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
}

pub(super) fn delete_forward() -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);

    if cursor >= len {
        return false;
    }

    // SAFETY: Single-threaded buffer access
    let deleted_char = unsafe { EDITOR_BUFFER[cursor] };
    push_undo(UndoOpType::Delete, cursor, &[deleted_char]);

    // SAFETY: Single-threaded buffer access
    unsafe {
        for i in cursor..len - 1 {
            EDITOR_BUFFER[i] = EDITOR_BUFFER[i + 1];
        }
        EDITOR_BUFFER[len - 1] = 0;
    }

    EDITOR_LEN.store(len - 1, Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
}

pub(super) fn delete_selection() -> bool {
    if !EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
        return false;
    }

    let start = EDITOR_SELECTION_START.load(Ordering::Relaxed);
    let end = EDITOR_SELECTION_END.load(Ordering::Relaxed);
    let (sel_start, sel_end) = if start < end { (start, end) } else { (end, start) };

    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let del_len = sel_end - sel_start;

    if del_len == 0 || sel_end > len {
        return false;
    }

    if del_len <= UNDO_DATA_SIZE {
        let mut deleted = [0u8; UNDO_DATA_SIZE];
        // SAFETY: Single-threaded buffer access
        unsafe {
            for i in 0..del_len {
                deleted[i] = EDITOR_BUFFER[sel_start + i];
            }
        }
        push_undo(UndoOpType::Delete, sel_start, &deleted[..del_len]);
    }

    // SAFETY: Single-threaded buffer access
    unsafe {
        for i in sel_start..len - del_len {
            EDITOR_BUFFER[i] = EDITOR_BUFFER[i + del_len];
        }
        for i in len - del_len..len {
            EDITOR_BUFFER[i] = 0;
        }
    }

    EDITOR_LEN.store(len - del_len, Ordering::Relaxed);
    EDITOR_CURSOR.store(sel_start, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
}

pub(super) fn insert_tab() -> bool {
    insert_str(b"    ")
}

pub(super) fn insert_newline() -> bool {
    insert_char(b'\n')
}

pub(super) fn load_content(data: &[u8]) {
    let copy_len = data.len().min(BUFFER_SIZE - 1);
    // SAFETY: Single-threaded buffer access
    unsafe {
        for i in 0..copy_len {
            EDITOR_BUFFER[i] = data[i];
        }
        for i in copy_len..BUFFER_SIZE {
            EDITOR_BUFFER[i] = 0;
        }
    }
    EDITOR_LEN.store(copy_len, Ordering::Relaxed);
    EDITOR_CURSOR.store(0, Ordering::Relaxed);
    EDITOR_SCROLL_Y.store(0, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn select_all() {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if len > 0 {
        EDITOR_SELECTION_START.store(0, Ordering::Relaxed);
        EDITOR_SELECTION_END.store(len, Ordering::Relaxed);
        EDITOR_HAS_SELECTION.store(true, Ordering::Relaxed);
        EDITOR_CURSOR.store(len, Ordering::Relaxed);
    }
}

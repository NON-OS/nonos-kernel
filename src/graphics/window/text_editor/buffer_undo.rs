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

pub(super) fn push_undo(op_type: UndoOpType, cursor_pos: usize, data: &[u8]) {
    let data_len = data.len().min(UNDO_DATA_SIZE);
    let mut entry = UndoEntry::empty();
    entry.op_type = op_type;
    entry.cursor_pos = cursor_pos;
    entry.data_len = data_len;
    for i in 0..data_len {
        entry.data[i] = data[i];
    }

    let top = UNDO_TOP.load(Ordering::Relaxed);
    let new_top = if top >= UNDO_STACK_SIZE { 0 } else { top };

    // SAFETY: Single-threaded access to undo stack
    unsafe {
        UNDO_STACK[new_top] = entry;
    }
    UNDO_TOP.store(new_top + 1, Ordering::Relaxed);
    REDO_TOP.store(0, Ordering::Relaxed);
}

pub(super) fn push_redo(entry: UndoEntry) {
    let top = REDO_TOP.load(Ordering::Relaxed);
    if top >= UNDO_STACK_SIZE {
        return;
    }
    // SAFETY: Single-threaded access to redo stack
    unsafe {
        REDO_STACK[top] = entry;
    }
    REDO_TOP.store(top + 1, Ordering::Relaxed);
}

pub(super) fn pop_undo() -> Option<UndoEntry> {
    let top = UNDO_TOP.load(Ordering::Relaxed);
    if top == 0 {
        return None;
    }
    UNDO_TOP.store(top - 1, Ordering::Relaxed);
    // SAFETY: Single-threaded access to undo stack
    unsafe {
        let entry = UNDO_STACK[top - 1];
        if entry.op_type == UndoOpType::None {
            return None;
        }
        Some(entry)
    }
}

pub(super) fn pop_redo() -> Option<UndoEntry> {
    let top = REDO_TOP.load(Ordering::Relaxed);
    if top == 0 {
        return None;
    }
    REDO_TOP.store(top - 1, Ordering::Relaxed);
    // SAFETY: Single-threaded access to redo stack
    unsafe {
        let entry = REDO_STACK[top - 1];
        if entry.op_type == UndoOpType::None {
            return None;
        }
        Some(entry)
    }
}

pub(super) fn undo() -> bool {
    let entry = match pop_undo() {
        Some(e) => e,
        None => return false,
    };

    match entry.op_type {
        UndoOpType::Insert => {
            let len = EDITOR_LEN.load(Ordering::Relaxed);
            let start = entry.cursor_pos;
            let del_len = entry.data_len;

            if start + del_len > len {
                return false;
            }

            // SAFETY: Single-threaded buffer access
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
            push_redo(entry);
        }
        UndoOpType::Delete => {
            let len = EDITOR_LEN.load(Ordering::Relaxed);
            let pos = entry.cursor_pos;
            let ins_len = entry.data_len;

            if len + ins_len >= BUFFER_SIZE {
                return false;
            }

            // SAFETY: Single-threaded buffer access
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
            push_redo(entry);
        }
        UndoOpType::None => return false,
    }

    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    true
}

pub(super) fn redo() -> bool {
    let entry = match pop_redo() {
        Some(e) => e,
        None => return false,
    };

    match entry.op_type {
        UndoOpType::Insert => {
            let len = EDITOR_LEN.load(Ordering::Relaxed);
            let pos = entry.cursor_pos;
            let ins_len = entry.data_len;

            if len + ins_len >= BUFFER_SIZE {
                return false;
            }

            // SAFETY: Single-threaded buffer access
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

            let top = UNDO_TOP.load(Ordering::Relaxed);
            if top < UNDO_STACK_SIZE {
                // SAFETY: Single-threaded undo stack access
                unsafe { UNDO_STACK[top] = entry; }
                UNDO_TOP.store(top + 1, Ordering::Relaxed);
            }
        }
        UndoOpType::Delete => {
            let len = EDITOR_LEN.load(Ordering::Relaxed);
            let start = entry.cursor_pos;
            let del_len = entry.data_len;

            if start + del_len > len {
                return false;
            }

            // SAFETY: Single-threaded buffer access
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

            let top = UNDO_TOP.load(Ordering::Relaxed);
            if top < UNDO_STACK_SIZE {
                // SAFETY: Single-threaded undo stack access
                unsafe { UNDO_STACK[top] = entry; }
                UNDO_TOP.store(top + 1, Ordering::Relaxed);
            }
        }
        UndoOpType::None => return false,
    }

    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    true
}

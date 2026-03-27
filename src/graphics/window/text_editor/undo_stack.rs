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
    for i in 0..data_len { entry.data[i] = data[i]; }
    let top = UNDO_TOP.load(Ordering::Relaxed);
    let new_top = if top >= UNDO_STACK_SIZE { 0 } else { top };
    unsafe { UNDO_STACK[new_top] = entry; }
    UNDO_TOP.store(new_top + 1, Ordering::Relaxed);
    REDO_TOP.store(0, Ordering::Relaxed);
}

pub(super) fn push_redo(entry: UndoEntry) {
    let top = REDO_TOP.load(Ordering::Relaxed);
    if top >= UNDO_STACK_SIZE { return; }
    unsafe { REDO_STACK[top] = entry; }
    REDO_TOP.store(top + 1, Ordering::Relaxed);
}

pub(super) fn pop_undo() -> Option<UndoEntry> {
    let top = UNDO_TOP.load(Ordering::Relaxed);
    if top == 0 { return None; }
    UNDO_TOP.store(top - 1, Ordering::Relaxed);
    unsafe {
        let entry = UNDO_STACK[top - 1];
        if entry.op_type == UndoOpType::None { return None; }
        Some(entry)
    }
}

pub(super) fn pop_redo() -> Option<UndoEntry> {
    let top = REDO_TOP.load(Ordering::Relaxed);
    if top == 0 { return None; }
    REDO_TOP.store(top - 1, Ordering::Relaxed);
    unsafe {
        let entry = REDO_STACK[top - 1];
        if entry.op_type == UndoOpType::None { return None; }
        Some(entry)
    }
}

pub(super) fn push_to_undo_stack(entry: UndoEntry) {
    let top = UNDO_TOP.load(Ordering::Relaxed);
    if top < UNDO_STACK_SIZE {
        unsafe { UNDO_STACK[top] = entry; }
        UNDO_TOP.store(top + 1, Ordering::Relaxed);
    }
}

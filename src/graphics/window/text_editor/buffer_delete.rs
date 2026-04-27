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

pub(super) fn delete_backward() -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    if cursor == 0 || len == 0 {
        return false;
    }
    let del = unsafe { EDITOR_BUFFER[cursor - 1] };
    push_undo(UndoOpType::Delete, cursor - 1, &[del]);
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
    let del = unsafe { EDITOR_BUFFER[cursor] };
    push_undo(UndoOpType::Delete, cursor, &[del]);
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
    let s = EDITOR_SELECTION_START.load(Ordering::Relaxed);
    let e = EDITOR_SELECTION_END.load(Ordering::Relaxed);
    let (start, end) = if s < e { (s, e) } else { (e, s) };
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let del_len = end - start;
    if del_len == 0 || end > len {
        return false;
    }
    if del_len <= UNDO_DATA_SIZE {
        let mut deleted = [0u8; UNDO_DATA_SIZE];
        unsafe {
            for i in 0..del_len {
                deleted[i] = EDITOR_BUFFER[start + i];
            }
        }
        push_undo(UndoOpType::Delete, start, &deleted[..del_len]);
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
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
}

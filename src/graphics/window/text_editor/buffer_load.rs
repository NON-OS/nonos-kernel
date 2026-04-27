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

pub(super) fn load_content(data: &[u8]) {
    let copy_len = data.len().min(BUFFER_SIZE - 1);
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

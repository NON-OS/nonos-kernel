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

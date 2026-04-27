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

pub(super) fn add_comment(start: usize, prefix: &[u8]) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    if len + prefix.len() >= BUFFER_SIZE {
        return false;
    }
    unsafe {
        for i in (start..len).rev() {
            EDITOR_BUFFER[i + prefix.len()] = EDITOR_BUFFER[i];
        }
        for (i, &ch) in prefix.iter().enumerate() {
            EDITOR_BUFFER[start + i] = ch;
        }
    }
    EDITOR_LEN.store(len + prefix.len(), Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    EDITOR_CURSOR.store(cursor + prefix.len(), Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    true
}

pub(super) fn remove_comment(start: usize, prefix: &[u8]) -> bool {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    let mut pos = start;
    while pos < len && unsafe { EDITOR_BUFFER[pos] } == b' ' {
        pos += 1;
    }
    unsafe {
        for i in pos + prefix.len()..len {
            EDITOR_BUFFER[i - prefix.len()] = EDITOR_BUFFER[i];
        }
        for i in len - prefix.len()..len {
            EDITOR_BUFFER[i] = 0;
        }
    }
    EDITOR_LEN.store(len - prefix.len(), Ordering::Relaxed);
    let cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
    if cursor >= prefix.len() {
        EDITOR_CURSOR.store(cursor - prefix.len(), Ordering::Relaxed);
    }
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    true
}

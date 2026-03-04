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
use super::find_state::*;
use super::find_search::{find_all, find_next};

pub fn replace_one() -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let pattern_len = FIND_LEN.load(Ordering::Relaxed);
    let replace_len = REPLACE_LEN.load(Ordering::Relaxed);
    let editor_len = EDITOR_LEN.load(Ordering::Relaxed);

    let pos = unsafe { MATCH_POSITIONS[current] };

    let new_len = editor_len - pattern_len + replace_len;
    if new_len >= BUFFER_SIZE {
        return false;
    }

    unsafe {
        if pattern_len > 0 {
            for i in pos..editor_len - pattern_len {
                EDITOR_BUFFER[i] = EDITOR_BUFFER[i + pattern_len];
            }
            for i in editor_len - pattern_len..editor_len {
                EDITOR_BUFFER[i] = 0;
            }
        }

        if replace_len > 0 {
            let new_editor_len = editor_len - pattern_len;
            for i in (pos..new_editor_len).rev() {
                EDITOR_BUFFER[i + replace_len] = EDITOR_BUFFER[i];
            }
            for i in 0..replace_len {
                EDITOR_BUFFER[pos + i] = REPLACE_BUFFER[i];
            }
        }
    }

    EDITOR_LEN.store(new_len, Ordering::Relaxed);
    EDITOR_MODIFIED.store(true, Ordering::Relaxed);

    find_all();
    find_next();

    true
}

pub fn replace_all() -> usize {
    let mut replaced = 0usize;

    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return 0;
    }

    let pattern_len = FIND_LEN.load(Ordering::Relaxed);
    let replace_len = REPLACE_LEN.load(Ordering::Relaxed);

    for i in (0..count).rev() {
        let pos = unsafe { MATCH_POSITIONS[i] };
        let editor_len = EDITOR_LEN.load(Ordering::Relaxed);

        let new_len = editor_len - pattern_len + replace_len;
        if new_len >= BUFFER_SIZE {
            break;
        }

        unsafe {
            if pattern_len > 0 {
                for j in pos..editor_len - pattern_len {
                    EDITOR_BUFFER[j] = EDITOR_BUFFER[j + pattern_len];
                }
                for j in editor_len - pattern_len..editor_len {
                    EDITOR_BUFFER[j] = 0;
                }
            }

            if replace_len > 0 {
                let new_editor_len = editor_len - pattern_len;
                for j in (pos..new_editor_len).rev() {
                    EDITOR_BUFFER[j + replace_len] = EDITOR_BUFFER[j];
                }
                for j in 0..replace_len {
                    EDITOR_BUFFER[pos + j] = REPLACE_BUFFER[j];
                }
            }
        }

        EDITOR_LEN.store(new_len, Ordering::Relaxed);
        replaced += 1;
    }

    if replaced > 0 {
        EDITOR_MODIFIED.store(true, Ordering::Relaxed);
    }

    MATCH_COUNT.store(0, Ordering::Relaxed);
    CURRENT_MATCH.store(0, Ordering::Relaxed);

    replaced
}

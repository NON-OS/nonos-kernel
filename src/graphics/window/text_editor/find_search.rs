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
use super::cursor;
use super::find_state::*;

fn bytes_match(a: u8, b: u8, case_sensitive: bool) -> bool {
    if case_sensitive {
        a == b
    } else {
        let a_lower = if a >= b'A' && a <= b'Z' { a + 32 } else { a };
        let b_lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        a_lower == b_lower
    }
}

pub(super) fn find_all() -> usize {
    let pattern_len = FIND_LEN.load(Ordering::Relaxed);
    if pattern_len == 0 {
        MATCH_COUNT.store(0, Ordering::Relaxed);
        return 0;
    }

    let editor_len = EDITOR_LEN.load(Ordering::Relaxed);
    let case_sensitive = CASE_SENSITIVE.load(Ordering::Relaxed);
    let mut count = 0usize;

    if pattern_len > editor_len {
        MATCH_COUNT.store(0, Ordering::Relaxed);
        return 0;
    }

    unsafe {
        let mut i = 0usize;
        while i <= editor_len - pattern_len && count < MAX_MATCHES {
            let mut matched = true;
            for j in 0..pattern_len {
                if !bytes_match(EDITOR_BUFFER[i + j], FIND_BUFFER[j], case_sensitive) {
                    matched = false;
                    break;
                }
            }

            if matched {
                MATCH_POSITIONS[count] = i;
                count += 1;
            }
            i += 1;
        }
    }

    MATCH_COUNT.store(count, Ordering::Relaxed);

    if count > 0 {
        let current = CURRENT_MATCH.load(Ordering::Relaxed);
        if current >= count {
            CURRENT_MATCH.store(0, Ordering::Relaxed);
        }
    }

    count
}

pub fn find_next() -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let next = if current + 1 >= count { 0 } else { current + 1 };

    CURRENT_MATCH.store(next, Ordering::Relaxed);
    goto_current_match()
}

pub fn find_prev() -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let prev = if current == 0 { count - 1 } else { current - 1 };

    CURRENT_MATCH.store(prev, Ordering::Relaxed);
    goto_current_match()
}

fn goto_current_match() -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let pattern_len = FIND_LEN.load(Ordering::Relaxed);

    let pos = unsafe { MATCH_POSITIONS[current] };

    cursor::set_position(pos);

    EDITOR_SELECTION_START.store(pos, Ordering::Relaxed);
    EDITOR_SELECTION_END.store(pos + pattern_len, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(true, Ordering::Relaxed);

    let visible_lines = 20usize;
    cursor::ensure_visible(visible_lines);

    true
}

pub(super) fn clear_highlights() {
    MATCH_COUNT.store(0, Ordering::Relaxed);
    CURRENT_MATCH.store(0, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
}

pub(super) fn is_match_position(pos: usize) -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    let pattern_len = FIND_LEN.load(Ordering::Relaxed);

    if count == 0 || pattern_len == 0 {
        return false;
    }

    unsafe {
        for i in 0..count {
            let start = MATCH_POSITIONS[i];
            let end = start + pattern_len;
            if pos >= start && pos < end {
                return true;
            }
        }
    }

    false
}

pub(super) fn is_current_match_position(pos: usize) -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let pattern_len = FIND_LEN.load(Ordering::Relaxed);

    let start = unsafe { MATCH_POSITIONS[current] };
    let end = start + pattern_len;

    pos >= start && pos < end
}

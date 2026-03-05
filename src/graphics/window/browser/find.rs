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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use super::state::{PAGE_LINES, SCROLL_OFFSET};

pub(super) const MAX_SEARCH_LEN: usize = 64;
pub(super) const MAX_MATCHES: usize = 128;

pub(crate) static FIND_ACTIVE: AtomicBool = AtomicBool::new(false);
pub(crate) static FIND_BUFFER: Mutex<[u8; MAX_SEARCH_LEN]> = Mutex::new([0u8; MAX_SEARCH_LEN]);
pub(crate) static FIND_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FIND_CURSOR: AtomicUsize = AtomicUsize::new(0);
pub(crate) static MATCH_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(crate) static CURRENT_MATCH: AtomicUsize = AtomicUsize::new(0);

pub(crate) static MATCHES: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());

pub fn open_find() {
    FIND_ACTIVE.store(true, Ordering::Relaxed);
    FIND_CURSOR.store(FIND_LEN.load(Ordering::Relaxed), Ordering::Relaxed);
}

pub fn close_find() {
    FIND_ACTIVE.store(false, Ordering::Relaxed);
    clear_matches();
}

pub fn is_active() -> bool {
    FIND_ACTIVE.load(Ordering::Relaxed)
}

pub(super) fn insert_char(ch: u8) {
    let mut buf = FIND_BUFFER.lock();
    let len = FIND_LEN.load(Ordering::Relaxed);
    let cursor = FIND_CURSOR.load(Ordering::Relaxed);

    if len >= MAX_SEARCH_LEN - 1 {
        return;
    }

    for i in (cursor..len).rev() {
        buf[i + 1] = buf[i];
    }
    buf[cursor] = ch;

    FIND_LEN.store(len + 1, Ordering::Relaxed);
    FIND_CURSOR.store(cursor + 1, Ordering::Relaxed);

    find_all();
}

pub(super) fn delete_backward() {
    let mut buf = FIND_BUFFER.lock();
    let len = FIND_LEN.load(Ordering::Relaxed);
    let cursor = FIND_CURSOR.load(Ordering::Relaxed);

    if cursor == 0 || len == 0 {
        return;
    }

    for i in cursor..len {
        buf[i - 1] = buf[i];
    }
    buf[len - 1] = 0;

    FIND_LEN.store(len - 1, Ordering::Relaxed);
    FIND_CURSOR.store(cursor - 1, Ordering::Relaxed);

    find_all();
}

pub fn get_pattern() -> String {
    let buf = FIND_BUFFER.lock();
    let len = FIND_LEN.load(Ordering::Relaxed);
    if len > 0 {
        core::str::from_utf8(&buf[..len])
            .map(String::from)
            .unwrap_or_default()
    } else {
        String::new()
    }
}

pub(crate) fn get_pattern_len() -> usize {
    FIND_LEN.load(Ordering::Relaxed)
}

pub fn get_cursor() -> usize {
    FIND_CURSOR.load(Ordering::Relaxed)
}

fn char_match(a: u8, b: u8) -> bool {
    let a_lower = if a >= b'A' && a <= b'Z' { a + 32 } else { a };
    let b_lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
    a_lower == b_lower
}

pub(super) fn find_all() -> usize {
    let pattern_len = FIND_LEN.load(Ordering::Relaxed);
    if pattern_len == 0 {
        clear_matches();
        return 0;
    }

    let pattern = {
        let buf = FIND_BUFFER.lock();
        let mut p = [0u8; MAX_SEARCH_LEN];
        p[..pattern_len].copy_from_slice(&buf[..pattern_len]);
        p
    };

    let mut matches_vec = MATCHES.lock();
    matches_vec.clear();

    let lines = PAGE_LINES.lock();
    for (line_idx, (line_text, _color)) in lines.iter().enumerate() {
        if matches_vec.len() >= MAX_MATCHES {
            break;
        }

        let line_bytes = line_text.as_bytes();
        if line_bytes.len() < pattern_len {
            continue;
        }

        let mut i = 0;
        while i <= line_bytes.len() - pattern_len && matches_vec.len() < MAX_MATCHES {
            let mut matched = true;
            for j in 0..pattern_len {
                if !char_match(line_bytes[i + j], pattern[j]) {
                    matched = false;
                    break;
                }
            }

            if matched {
                matches_vec.push((line_idx, i, i + pattern_len));
                i += pattern_len;
            } else {
                i += 1;
            }
        }
    }

    let count = matches_vec.len();
    MATCH_COUNT.store(count, Ordering::Relaxed);

    if count > 0 {
        let current = CURRENT_MATCH.load(Ordering::Relaxed);
        if current >= count {
            CURRENT_MATCH.store(0, Ordering::Relaxed);
        }
    }

    count
}

pub fn get_match_count() -> usize {
    MATCH_COUNT.load(Ordering::Relaxed)
}

pub fn get_current_match() -> usize {
    CURRENT_MATCH.load(Ordering::Relaxed)
}

pub fn find_next() -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let next = if current + 1 >= count { 0 } else { current + 1 };
    CURRENT_MATCH.store(next, Ordering::Relaxed);

    scroll_to_match(next);
    true
}

pub fn find_prev() -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let prev = if current == 0 { count - 1 } else { current - 1 };
    CURRENT_MATCH.store(prev, Ordering::Relaxed);

    scroll_to_match(prev);
    true
}

fn scroll_to_match(match_idx: usize) {
    let matches_vec = MATCHES.lock();
    if match_idx >= matches_vec.len() {
        return;
    }

    let (line_idx, _, _) = matches_vec[match_idx];

    let visible_lines = 20usize;
    let current_scroll = SCROLL_OFFSET.load(Ordering::Relaxed);

    if line_idx < current_scroll {
        SCROLL_OFFSET.store(line_idx.saturating_sub(2), Ordering::Relaxed);
    } else if line_idx >= current_scroll + visible_lines {
        SCROLL_OFFSET.store(line_idx.saturating_sub(visible_lines / 2), Ordering::Relaxed);
    }
}

pub(super) fn clear_matches() {
    let mut matches_vec = MATCHES.lock();
    matches_vec.clear();
    MATCH_COUNT.store(0, Ordering::Relaxed);
    CURRENT_MATCH.store(0, Ordering::Relaxed);
}

pub fn clear_find() {
    let mut buf = FIND_BUFFER.lock();
    *buf = [0u8; MAX_SEARCH_LEN];
    FIND_LEN.store(0, Ordering::Relaxed);
    FIND_CURSOR.store(0, Ordering::Relaxed);
    clear_matches();
}

pub(crate) fn is_match_position(line: usize, char_pos: usize) -> bool {
    let matches_vec = MATCHES.lock();
    for (l, start, end) in matches_vec.iter() {
        if *l == line && char_pos >= *start && char_pos < *end {
            return true;
        }
    }
    false
}

pub(crate) fn is_current_match_position(line: usize, char_pos: usize) -> bool {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return false;
    }

    let current = CURRENT_MATCH.load(Ordering::Relaxed);
    let matches_vec = MATCHES.lock();
    if current >= matches_vec.len() {
        return false;
    }

    let (l, start, end) = matches_vec[current];
    l == line && char_pos >= start && char_pos < end
}

pub(super) fn handle_key(ch: u8) {
    match ch {
        27 => close_find(),
        8 | 127 => delete_backward(),
        13 => { find_next(); }
        32..=126 => insert_char(ch),
        _ => {}
    }
}

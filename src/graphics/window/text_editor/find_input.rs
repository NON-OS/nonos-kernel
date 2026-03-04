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
use super::find_state::*;
use super::find_search::{find_all, find_next, clear_highlights};
use super::find_replace::replace_one;

pub(super) fn find_insert_char(ch: u8) {
    let len = FIND_LEN.load(Ordering::Relaxed);
    if len >= FIND_BUFFER_SIZE - 1 {
        return;
    }

    let cursor = FIND_CURSOR.load(Ordering::Relaxed);
    unsafe {
        for i in (cursor..len).rev() {
            FIND_BUFFER[i + 1] = FIND_BUFFER[i];
        }
        FIND_BUFFER[cursor] = ch;
    }

    FIND_LEN.store(len + 1, Ordering::Relaxed);
    FIND_CURSOR.store(cursor + 1, Ordering::Relaxed);

    find_all();
}

pub(super) fn find_delete_backward() {
    let len = FIND_LEN.load(Ordering::Relaxed);
    let cursor = FIND_CURSOR.load(Ordering::Relaxed);

    if cursor == 0 || len == 0 {
        return;
    }

    unsafe {
        for i in cursor..len {
            FIND_BUFFER[i - 1] = FIND_BUFFER[i];
        }
        FIND_BUFFER[len - 1] = 0;
    }

    FIND_LEN.store(len - 1, Ordering::Relaxed);
    FIND_CURSOR.store(cursor - 1, Ordering::Relaxed);

    find_all();
}

pub(super) fn replace_insert_char(ch: u8) {
    let len = REPLACE_LEN.load(Ordering::Relaxed);
    if len >= FIND_BUFFER_SIZE - 1 {
        return;
    }

    unsafe {
        REPLACE_BUFFER[len] = ch;
    }
    REPLACE_LEN.store(len + 1, Ordering::Relaxed);
}

pub(super) fn replace_delete_backward() {
    let len = REPLACE_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return;
    }

    unsafe {
        REPLACE_BUFFER[len - 1] = 0;
    }
    REPLACE_LEN.store(len - 1, Ordering::Relaxed);
}

pub(super) fn _get_find_pattern() -> &'static [u8] {
    let len = FIND_LEN.load(Ordering::Relaxed);
    unsafe { &FIND_BUFFER[..len] }
}

pub(super) fn _get_replace_pattern() -> &'static [u8] {
    let len = REPLACE_LEN.load(Ordering::Relaxed);
    unsafe { &REPLACE_BUFFER[..len] }
}

pub fn set_find_pattern(pattern: &[u8]) {
    let len = pattern.len().min(FIND_BUFFER_SIZE - 1);
    unsafe {
        for i in 0..len {
            FIND_BUFFER[i] = pattern[i];
        }
        for i in len..FIND_BUFFER_SIZE {
            FIND_BUFFER[i] = 0;
        }
    }
    FIND_LEN.store(len, Ordering::Relaxed);
    FIND_CURSOR.store(len, Ordering::Relaxed);
    find_all();
}

pub fn set_replace_pattern(pattern: &[u8]) {
    let len = pattern.len().min(FIND_BUFFER_SIZE - 1);
    unsafe {
        for i in 0..len {
            REPLACE_BUFFER[i] = pattern[i];
        }
        for i in len..FIND_BUFFER_SIZE {
            REPLACE_BUFFER[i] = 0;
        }
    }
    REPLACE_LEN.store(len, Ordering::Relaxed);
}

pub(super) fn handle_find_key(ch: u8) {
    match ch {
        27 => {
            close_find();
        }
        8 | 127 => {
            find_delete_backward();
        }
        13 => {
            find_next();
        }
        32..=126 => {
            find_insert_char(ch);
        }
        _ => {}
    }
}

pub(super) fn handle_replace_key(ch: u8) {
    match ch {
        27 => {
            close_find();
        }
        8 | 127 => {
            replace_delete_backward();
        }
        13 => {
            replace_one();
        }
        32..=126 => {
            replace_insert_char(ch);
        }
        _ => {}
    }
}

pub(super) fn clear_find() {
    unsafe {
        for i in 0..FIND_BUFFER_SIZE {
            FIND_BUFFER[i] = 0;
        }
    }
    FIND_LEN.store(0, Ordering::Relaxed);
    FIND_CURSOR.store(0, Ordering::Relaxed);
    clear_highlights();
}

pub(super) fn clear_replace() {
    unsafe {
        for i in 0..FIND_BUFFER_SIZE {
            REPLACE_BUFFER[i] = 0;
        }
    }
    REPLACE_LEN.store(0, Ordering::Relaxed);
}

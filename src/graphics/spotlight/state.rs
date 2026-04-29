// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

static OPEN: AtomicBool = AtomicBool::new(false);
static SELECTED_IDX: AtomicUsize = AtomicUsize::new(0);
static QUERY_LEN: AtomicU8 = AtomicU8::new(0);
static QUERY: [AtomicU8; 64] = {
    const INIT: AtomicU8 = AtomicU8::new(0);
    [INIT; 64]
};

pub fn is_open() -> bool {
    OPEN.load(Ordering::Relaxed)
}

pub fn open() {
    OPEN.store(true, Ordering::Relaxed);
    clear_query();
}

pub fn close() {
    OPEN.store(false, Ordering::Relaxed);
    clear_query();
}

pub fn toggle() {
    if is_open() { close(); } else { open(); }
}

pub(super) fn get_query() -> ([u8; 64], usize) {
    let len = QUERY_LEN.load(Ordering::Relaxed) as usize;
    let mut buf = [0u8; 64];
    for i in 0..len.min(64) {
        buf[i] = QUERY[i].load(Ordering::Relaxed);
    }
    (buf, len)
}

pub(super) fn push_char(c: u8) {
    let len = QUERY_LEN.load(Ordering::Relaxed) as usize;
    if len < 63 {
        QUERY[len].store(c, Ordering::Relaxed);
        QUERY_LEN.store((len + 1) as u8, Ordering::Relaxed);
    }
}

pub(super) fn pop_char() {
    let len = QUERY_LEN.load(Ordering::Relaxed);
    if len > 0 {
        QUERY_LEN.store(len - 1, Ordering::Relaxed);
    }
}

pub(super) fn clear_query() {
    QUERY_LEN.store(0, Ordering::Relaxed);
    SELECTED_IDX.store(0, Ordering::Relaxed);
}

pub(super) fn get_selected() -> usize {
    SELECTED_IDX.load(Ordering::Relaxed)
}

pub(super) fn select_next(max: usize) {
    let cur = SELECTED_IDX.load(Ordering::Relaxed);
    SELECTED_IDX.store((cur + 1).min(max.saturating_sub(1)), Ordering::Relaxed);
}

pub(super) fn select_prev() {
    let cur = SELECTED_IDX.load(Ordering::Relaxed);
    SELECTED_IDX.store(cur.saturating_sub(1), Ordering::Relaxed);
}

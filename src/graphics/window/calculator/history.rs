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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

pub const MAX_HISTORY: usize = 16;

#[derive(Clone, Copy)]
pub struct HistoryEntry {
    pub operand1: i64,
    pub operand2: i64,
    pub operator: u8,
    pub result: i64,
}

static mut HISTORY: [HistoryEntry; MAX_HISTORY] =
    [HistoryEntry { operand1: 0, operand2: 0, operator: 0, result: 0 }; MAX_HISTORY];
static HISTORY_COUNT: AtomicU8 = AtomicU8::new(0);
static HISTORY_VISIBLE: AtomicBool = AtomicBool::new(false);

pub fn add_entry(operand1: i64, operand2: i64, operator: u8, result: i64) {
    let count = HISTORY_COUNT.load(Ordering::Relaxed) as usize;
    let idx = count.min(MAX_HISTORY - 1);
    unsafe {
        if count >= MAX_HISTORY {
            for i in 0..MAX_HISTORY - 1 {
                HISTORY[i] = HISTORY[i + 1];
            }
        }
        HISTORY[idx] = HistoryEntry { operand1, operand2, operator, result };
    }
    if count < MAX_HISTORY {
        HISTORY_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn get_entry(index: usize) -> Option<HistoryEntry> {
    let count = HISTORY_COUNT.load(Ordering::Relaxed) as usize;
    if index < count {
        unsafe { Some(HISTORY[index]) }
    } else {
        None
    }
}

pub fn get_count() -> usize {
    HISTORY_COUNT.load(Ordering::Relaxed) as usize
}
pub fn clear() {
    HISTORY_COUNT.store(0, Ordering::Relaxed);
}
pub fn is_visible() -> bool {
    HISTORY_VISIBLE.load(Ordering::Relaxed)
}
pub fn toggle_visible() {
    HISTORY_VISIBLE.fetch_xor(true, Ordering::Relaxed);
}
pub fn set_visible(visible: bool) {
    HISTORY_VISIBLE.store(visible, Ordering::Relaxed);
}

pub fn get_last_result() -> Option<i64> {
    let count = HISTORY_COUNT.load(Ordering::Relaxed) as usize;
    if count > 0 {
        unsafe { Some(HISTORY[count - 1].result) }
    } else {
        None
    }
}

pub fn operator_char(op: u8) -> u8 {
    match op {
        1 => b'+',
        2 => b'-',
        3 => b'*',
        4 => b'/',
        _ => b'?',
    }
}

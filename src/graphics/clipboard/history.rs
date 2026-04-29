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

use super::data::ContentType;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const HISTORY_SIZE: usize = 10;
const MAX_ITEM_SIZE: usize = 1024;

#[derive(Clone, Copy)]
pub struct HistoryItem {
    pub data: [u8; MAX_ITEM_SIZE],
    pub len: usize,
    pub content_type: ContentType,
    pub timestamp: u64,
}

impl HistoryItem {
    pub const fn empty() -> Self {
        Self { data: [0u8; MAX_ITEM_SIZE], len: 0, content_type: ContentType::Empty, timestamp: 0 }
    }
}

static mut HISTORY: [HistoryItem; HISTORY_SIZE] = [HistoryItem::empty(); HISTORY_SIZE];
static HISTORY_HEAD: AtomicUsize = AtomicUsize::new(0);
static HISTORY_COUNT: AtomicUsize = AtomicUsize::new(0);

pub(super) fn add_to_history(data: &[u8], content_type: ContentType) {
    let len = data.len().min(MAX_ITEM_SIZE);
    let head = HISTORY_HEAD.load(Ordering::Relaxed);
    unsafe {
        for i in 0..len {
            HISTORY[head].data[i] = data[i];
        }
        HISTORY[head].len = len;
        HISTORY[head].content_type = content_type;
        HISTORY[head].timestamp = crate::time::timestamp_millis();
    }
    HISTORY_HEAD.store((head + 1) % HISTORY_SIZE, Ordering::Relaxed);
    let count = HISTORY_COUNT.load(Ordering::Relaxed);
    if count < HISTORY_SIZE {
        HISTORY_COUNT.store(count + 1, Ordering::Relaxed);
    }
}

pub fn history_count() -> usize {
    HISTORY_COUNT.load(Ordering::Relaxed)
}

pub fn get_history_item(idx: usize) -> Option<&'static HistoryItem> {
    let count = HISTORY_COUNT.load(Ordering::Relaxed);
    if idx >= count {
        return None;
    }
    let head = HISTORY_HEAD.load(Ordering::Relaxed);
    let actual_idx = (head + HISTORY_SIZE - 1 - idx) % HISTORY_SIZE;
    unsafe { Some(&HISTORY[actual_idx]) }
}

pub fn clear_history() {
    HISTORY_HEAD.store(0, Ordering::Relaxed);
    HISTORY_COUNT.store(0, Ordering::Relaxed);
}

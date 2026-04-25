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

use super::lock::{lock_heap, unlock_heap};
use super::state::*;
use super::types::BLOCK_MAGIC;
use core::sync::atomic::Ordering;

pub fn stats() -> (usize, usize, usize, usize) {
    (
        TOTAL_ALLOCATED.load(Ordering::Relaxed),
        TOTAL_FREED.load(Ordering::Relaxed),
        PEAK_USAGE.load(Ordering::Relaxed),
        free_space(),
    )
}

fn free_space() -> usize {
    if !HEAP_INIT.load(Ordering::Relaxed) {
        return 0;
    }

    lock_heap();

    let mut total: usize = 0;
    let mut current = unsafe { FREE_LIST };

    while !current.is_null() {
        unsafe {
            if (*current).magic == BLOCK_MAGIC {
                total += (*current).size;
            }
            current = (*current).next;
        }
    }

    unlock_heap();
    total
}

pub fn is_init() -> bool {
    HEAP_INIT.load(Ordering::Relaxed)
}

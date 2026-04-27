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

use super::super::PAGE_SIZE;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(super) const MAX_BITMAP_PAGES: usize = 256 * 1024;
pub(super) const BITMAP_SIZE: usize = MAX_BITMAP_PAGES / 64;

pub(super) static mut PAGE_BITMAP: [AtomicU64; BITMAP_SIZE] = {
    const INIT: AtomicU64 = AtomicU64::new(0xFFFF_FFFF_FFFF_FFFF);
    [INIT; BITMAP_SIZE]
};

pub(super) static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);
pub(super) static FREE_PAGES: AtomicUsize = AtomicUsize::new(0);
pub(super) static MAX_PHYS_ADDR: AtomicU64 = AtomicU64::new(0);
pub(super) static PMM_INIT: AtomicUsize = AtomicUsize::new(0);

pub fn total_pages() -> usize {
    TOTAL_PAGES.load(Ordering::Relaxed)
}

pub fn free_pages_count() -> usize {
    FREE_PAGES.load(Ordering::Relaxed)
}

pub fn used_pages() -> usize {
    total_pages().saturating_sub(free_pages_count())
}

pub fn memory_stats() -> (usize, usize, usize) {
    let total = total_pages() * PAGE_SIZE;
    let free = free_pages_count() * PAGE_SIZE;
    let used = total.saturating_sub(free);
    (total, used, free)
}

pub fn is_init() -> bool {
    PMM_INIT.load(Ordering::Relaxed) != 0
}

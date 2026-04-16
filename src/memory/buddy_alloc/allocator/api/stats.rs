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

use spin::Mutex;
use x86_64::VirtAddr;
use crate::memory::layout;
use super::super::super::error::BuddyAllocResult;
use super::super::super::stats::ALLOCATION_STATS;
use super::super::super::types::AllocStats;
use super::super::core::VmapAllocator;

pub(super) static VMAP_ALLOCATOR: Mutex<VmapAllocator> = Mutex::new(VmapAllocator::new());

pub fn init() -> BuddyAllocResult<()> { VMAP_ALLOCATOR.lock().init() }

pub fn get_allocation_stats() -> AllocStats {
    ALLOCATION_STATS.get_stats(VMAP_ALLOCATOR.lock().allocated_count())
}

pub fn is_valid_allocation(addr: VirtAddr) -> bool {
    VMAP_ALLOCATOR.lock().is_allocated(addr.as_u64())
}

pub fn get_allocation_size(addr: VirtAddr) -> Option<usize> {
    VMAP_ALLOCATOR.lock().get_size(addr.as_u64())
}

pub fn validate_range(addr: VirtAddr, size: usize) -> bool {
    let a = addr.as_u64();
    let end = match a.checked_add(size as u64) {
        Some(e) => e,
        None => return false,
    };
    let vmap_end = match layout::VMAP_BASE.checked_add(layout::VMAP_SIZE) {
        Some(e) => e,
        None => return false,
    };
    if a < layout::VMAP_BASE || end > vmap_end { return false; }
    VMAP_ALLOCATOR.lock().get_size(a).map(|s| size <= s).unwrap_or(false)
}

#[inline]
pub fn total_allocated() -> u64 { ALLOCATION_STATS.total_allocated() }

#[inline]
pub fn peak_allocated() -> u64 { ALLOCATION_STATS.peak_allocated() }

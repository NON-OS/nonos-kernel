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

use super::super::types::PageAllocatorStats;
use super::allocator::PageAllocator;
use super::globals::ALLOCATOR_STATS;
use core::sync::atomic::Ordering;

impl PageAllocator {
    pub(super) fn get_allocator_stats(&self) -> PageAllocatorStats {
        PageAllocatorStats {
            total_allocations: ALLOCATOR_STATS.total_allocations.load(Ordering::Relaxed),
            total_deallocations: ALLOCATOR_STATS.total_deallocations.load(Ordering::Relaxed),
            active_pages: ALLOCATOR_STATS.active_pages.load(Ordering::Relaxed),
            bytes_allocated: ALLOCATOR_STATS.bytes_allocated.load(Ordering::Relaxed),
            peak_pages: ALLOCATOR_STATS.peak_pages.load(Ordering::Relaxed),
            allocated_pages: self.allocated_pages.len(),
        }
    }
}

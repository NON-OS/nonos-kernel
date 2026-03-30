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

use super::super::types::ManagerStats;
use super::state::{MemoryManager, MEMORY_MANAGER};
use super::stats_internal::MEMORY_STATS;

impl MemoryManager {
    pub(super) fn get_stats(&self) -> ManagerStats {
        ManagerStats {
            total_regions: self.regions.len(),
            allocated_memory: MEMORY_STATS.total_allocated.load(Ordering::Relaxed),
            peak_memory: MEMORY_STATS.peak_usage.load(Ordering::Relaxed),
            allocations: MEMORY_STATS.allocations.load(Ordering::Relaxed),
            deallocations: MEMORY_STATS.deallocations.load(Ordering::Relaxed),
        }
    }
}

pub fn get_memory_stats() -> ManagerStats {
    MEMORY_MANAGER.lock().get_stats()
}

#[inline]
pub fn get_total_memory() -> u64 {
    MEMORY_STATS.total_allocated.load(Ordering::Relaxed)
}

#[inline]
pub fn get_peak_memory() -> u64 {
    MEMORY_STATS.peak_usage.load(Ordering::Relaxed)
}

#[inline]
pub fn get_allocation_count() -> u64 {
    MEMORY_STATS.allocations.load(Ordering::Relaxed)
}

#[inline]
pub fn get_deallocation_count() -> u64 {
    MEMORY_STATS.deallocations.load(Ordering::Relaxed)
}

#[inline]
pub fn get_region_count() -> usize {
    MEMORY_STATS.region_count.load(Ordering::Relaxed)
}

// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use super::types::AllocStats;
// ============================================================================
// GLOBAL STATS TRACKER + STATISTICS TRACKER
// ============================================================================
pub static ALLOCATION_STATS: AllocationStatistics = AllocationStatistics::new();
pub struct AllocationStatistics {
    total_allocated: AtomicU64,
    peak_allocated: AtomicU64,
    allocation_count: AtomicUsize,
    free_count: AtomicUsize,
}

impl AllocationStatistics {
    pub const fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            peak_allocated: AtomicU64::new(0),
            allocation_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
        }
    }
    pub fn record_allocation(&self, size: u64) {
        let new_total = self.total_allocated.fetch_add(size, Ordering::AcqRel) + size;
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        loop {
            let current_peak = self.peak_allocated.load(Ordering::Relaxed);
            if new_total <= current_peak {
                break;
            }
            match self.peak_allocated.compare_exchange_weak(
                current_peak,
                new_total,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    pub fn record_deallocation(&self, size: u64) {
        self.total_allocated.fetch_sub(size, Ordering::AcqRel);
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn total_allocated(&self) -> u64 {
        self.total_allocated.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn peak_allocated(&self) -> u64 {
        self.peak_allocated.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn allocation_count(&self) -> usize {
        self.allocation_count.load(Ordering::Relaxed)
    }

  #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count.load(Ordering::Relaxed)
    }

  pub fn get_stats(&self, active_ranges: usize) -> AllocStats {
        AllocStats {
            total_allocated: self.total_allocated(),
            peak_allocated: self.peak_allocated(),
            allocation_count: self.allocation_count(),
            free_count: self.free_count(),
            active_ranges,
        }
    }
}

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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(super) struct MemoryStats {
    pub total_allocated: AtomicU64,
    pub region_count: AtomicUsize,
    pub allocations: AtomicU64,
    pub deallocations: AtomicU64,
    pub peak_usage: AtomicU64,
}

impl MemoryStats {
    pub(super) const fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            region_count: AtomicUsize::new(0),
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            peak_usage: AtomicU64::new(0),
        }
    }

    pub(super) fn record_allocation(&self, size: u64) {
        let new_total = self.total_allocated.fetch_add(size, Ordering::AcqRel) + size;
        self.region_count.fetch_add(1, Ordering::Relaxed);
        self.allocations.fetch_add(1, Ordering::Relaxed);
        loop {
            let current_peak = self.peak_usage.load(Ordering::Relaxed);
            if new_total <= current_peak {
                break;
            }
            if self
                .peak_usage
                .compare_exchange_weak(current_peak, new_total, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    pub(super) fn record_deallocation(&self, size: u64) {
        self.total_allocated.fetch_sub(size, Ordering::AcqRel);
        self.region_count.fetch_sub(1, Ordering::Relaxed);
        self.deallocations.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) static MEMORY_STATS: MemoryStats = MemoryStats::new();

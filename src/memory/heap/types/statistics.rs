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

use super::stats::HeapStats;
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct HeapStatistics {
    pub total_size: AtomicUsize,
    pub current_usage: AtomicUsize,
    pub peak_usage: AtomicUsize,
    pub allocation_count: AtomicUsize,
    pub deallocation_count: AtomicUsize,
    pub total_allocated: core::sync::atomic::AtomicU64,
    pub total_deallocated: core::sync::atomic::AtomicU64,
}

impl HeapStatistics {
    pub const fn new() -> Self {
        Self {
            total_size: AtomicUsize::new(0),
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            allocation_count: AtomicUsize::new(0),
            deallocation_count: AtomicUsize::new(0),
            total_allocated: core::sync::atomic::AtomicU64::new(0),
            total_deallocated: core::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_allocation(&self, size: usize) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        self.total_allocated.fetch_add(size as u64, Ordering::Relaxed);
        let new_usage = self.current_usage.fetch_add(size, Ordering::AcqRel) + size;
        loop {
            let current_peak = self.peak_usage.load(Ordering::Relaxed);
            if new_usage <= current_peak {
                break;
            }
            if self
                .peak_usage
                .compare_exchange_weak(current_peak, new_usage, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn record_deallocation(&self, size: usize) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.total_deallocated.fetch_add(size as u64, Ordering::Relaxed);
        self.current_usage.fetch_sub(size, Ordering::AcqRel);
    }

    pub fn set_total_size(&self, size: usize) {
        self.total_size.store(size, Ordering::Release);
    }

    pub fn get_stats(&self) -> HeapStats {
        HeapStats {
            total_size: self.total_size.load(Ordering::Acquire),
            current_usage: self.current_usage.load(Ordering::Acquire),
            peak_usage: self.peak_usage.load(Ordering::Acquire),
            allocation_count: self.allocation_count.load(Ordering::Relaxed),
            total_allocated: self.total_allocated.load(Ordering::Relaxed),
            total_deallocated: self.total_deallocated.load(Ordering::Relaxed),
        }
    }
}

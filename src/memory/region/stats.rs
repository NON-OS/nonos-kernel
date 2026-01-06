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
pub struct RegionStatistics {
    pub(crate) total_regions: AtomicUsize,
    pub(crate) allocated_bytes: AtomicU64,
    pub(crate) free_bytes: AtomicU64,
    pub(crate) fragmentation_count: AtomicUsize,
    pub(crate) allocation_count: AtomicU64,
    pub(crate) deallocation_count: AtomicU64,
    pub(crate) merge_count: AtomicU64,
    pub(crate) split_count: AtomicU64,
}

impl RegionStatistics {
    pub const fn new() -> Self {
        Self {
            total_regions: AtomicUsize::new(0),
            allocated_bytes: AtomicU64::new(0),
            free_bytes: AtomicU64::new(0),
            fragmentation_count: AtomicUsize::new(0),
            allocation_count: AtomicU64::new(0),
            deallocation_count: AtomicU64::new(0),
            merge_count: AtomicU64::new(0),
            split_count: AtomicU64::new(0),
        }
    }

    pub fn record_allocation(&self, size: u64) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
    }

    pub fn record_deallocation(&self, size: u64) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        self.free_bytes.fetch_add(size, Ordering::Relaxed);
    }

    pub fn record_merge(&self) {
        self.merge_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_split(&self) {
        self.split_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_region(&self, size: u64, is_free: bool) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        if is_free {
            self.free_bytes.fetch_add(size, Ordering::Relaxed);
        } else {
            self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
        }
    }

    pub fn remove_region(&self, size: u64, is_free: bool) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        if is_free {
            self.free_bytes.fetch_sub(size, Ordering::Relaxed);
        } else {
            self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        }
    }

    pub fn total_regions(&self) -> usize {
        self.total_regions.load(Ordering::Relaxed)
    }

    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes.load(Ordering::Relaxed)
    }

    pub fn free_bytes(&self) -> u64 {
        self.free_bytes.load(Ordering::Relaxed)
    }

    pub fn allocation_count(&self) -> u64 {
        self.allocation_count.load(Ordering::Relaxed)
    }

    pub fn deallocation_count(&self) -> u64 {
        self.deallocation_count.load(Ordering::Relaxed)
    }

    pub fn merge_count(&self) -> u64 {
        self.merge_count.load(Ordering::Relaxed)
    }

    pub fn split_count(&self) -> u64 {
        self.split_count.load(Ordering::Relaxed)
    }
}

impl Default for RegionStatistics {
    fn default() -> Self {
        Self::new()
    }
}

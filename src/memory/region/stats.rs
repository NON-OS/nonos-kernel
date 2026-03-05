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

//! Region Statistics (Lock-Free)

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Internal lock-free region statistics.
pub struct RegionStatistics {
    /// Total number of regions
    pub(crate) total_regions: AtomicUsize,
    /// Total allocated bytes
    pub(crate) allocated_bytes: AtomicU64,
    /// Total free bytes
    pub(crate) free_bytes: AtomicU64,
    /// Number of fragments
    pub(crate) fragmentation_count: AtomicUsize,
    /// Number of allocations
    pub(crate) allocation_count: AtomicU64,
    /// Number of deallocations
    pub(crate) deallocation_count: AtomicU64,
    /// Number of merge operations
    pub(crate) merge_count: AtomicU64,
    /// Number of split operations
    pub(crate) split_count: AtomicU64,
}

impl RegionStatistics {
    /// Creates new statistics (all zeros).
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

    /// Records an allocation.
    pub fn record_allocation(&self, size: u64) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
    }

    /// Records a deallocation.
    pub fn record_deallocation(&self, size: u64) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        self.free_bytes.fetch_add(size, Ordering::Relaxed);
    }

    /// Records a merge operation.
    pub fn record_merge(&self) {
        self.merge_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a split operation.
    pub fn record_split(&self) {
        self.split_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds a region.
    pub fn add_region(&self, size: u64, is_free: bool) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        if is_free {
            self.free_bytes.fetch_add(size, Ordering::Relaxed);
        } else {
            self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
        }
    }

    /// Removes a region.
    pub fn remove_region(&self, size: u64, is_free: bool) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        if is_free {
            self.free_bytes.fetch_sub(size, Ordering::Relaxed);
        } else {
            self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        }
    }

    /// Returns total regions count.
    pub fn total_regions(&self) -> usize {
        self.total_regions.load(Ordering::Relaxed)
    }

    /// Returns allocated bytes.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes.load(Ordering::Relaxed)
    }

    /// Returns free bytes.
    pub fn free_bytes(&self) -> u64 {
        self.free_bytes.load(Ordering::Relaxed)
    }

    /// Returns allocation count.
    pub fn allocation_count(&self) -> u64 {
        self.allocation_count.load(Ordering::Relaxed)
    }

    /// Returns deallocation count.
    pub fn deallocation_count(&self) -> u64 {
        self.deallocation_count.load(Ordering::Relaxed)
    }

    /// Returns merge count.
    pub fn merge_count(&self) -> u64 {
        self.merge_count.load(Ordering::Relaxed)
    }

    /// Returns split count.
    pub fn split_count(&self) -> u64 {
        self.split_count.load(Ordering::Relaxed)
    }

    /// Returns fragmentation count (number of disjoint free regions).
    pub fn fragmentation_count(&self) -> usize {
        self.fragmentation_count.load(Ordering::Relaxed)
    }

    /// Increments the fragmentation count.
    pub fn record_fragmentation(&self) {
        self.fragmentation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the fragmentation count (when regions are merged).
    pub fn reduce_fragmentation(&self) {
        self.fragmentation_count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Default for RegionStatistics {
    fn default() -> Self {
        Self::new()
    }
}

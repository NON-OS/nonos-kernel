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

//! MMIO Statistics Tracking

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::types::MmioStatsSnapshot;

// ============================================================================
// GLOBAL STATISTICS
// ============================================================================

/// Global MMIO statistics instance.
pub static MMIO_STATS: MmioStats = MmioStats::new();

// ============================================================================
// STATISTICS TRACKER
// ============================================================================

/// Lock-free MMIO statistics.
pub struct MmioStats {
    /// Total mapped regions
    total_regions: AtomicUsize,
    /// Total mapped size
    total_mapped_size: AtomicU64,
    /// Read operations
    read_operations: AtomicU64,
    /// Write operations
    write_operations: AtomicU64,
    /// Next region ID
    next_region_id: AtomicU64,
}

impl MmioStats {
    /// Creates a new statistics tracker.
    pub const fn new() -> Self {
        Self {
            total_regions: AtomicUsize::new(0),
            total_mapped_size: AtomicU64::new(0),
            read_operations: AtomicU64::new(0),
            write_operations: AtomicU64::new(0),
            next_region_id: AtomicU64::new(1),
        }
    }

    /// Gets the next unique region ID.
    pub fn next_id(&self) -> u64 {
        self.next_region_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Records a region mapping.
    pub fn record_mapping(&self, size: usize) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Records a region unmapping.
    pub fn record_unmapping(&self, size: usize) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_sub(size as u64, Ordering::Relaxed);
    }

    /// Records a read operation.
    #[inline]
    pub fn record_read(&self) {
        self.read_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a write operation.
    #[inline]
    pub fn record_write(&self) {
        self.write_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns current region count.
    #[inline]
    pub fn total_regions(&self) -> usize {
        self.total_regions.load(Ordering::Relaxed)
    }

    /// Returns current mapped size.
    #[inline]
    pub fn total_mapped_size(&self) -> u64 {
        self.total_mapped_size.load(Ordering::Relaxed)
    }

    /// Returns read operation count.
    #[inline]
    pub fn read_operations(&self) -> u64 {
        self.read_operations.load(Ordering::Relaxed)
    }

    /// Returns write operation count.
    #[inline]
    pub fn write_operations(&self) -> u64 {
        self.write_operations.load(Ordering::Relaxed)
    }

    /// Returns a snapshot of all statistics.
    pub fn snapshot(&self) -> MmioStatsSnapshot {
        MmioStatsSnapshot {
            total_regions: self.total_regions(),
            total_mapped_size: self.total_mapped_size(),
            read_operations: self.read_operations(),
            write_operations: self.write_operations(),
        }
    }
}

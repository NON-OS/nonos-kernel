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
use super::types::MmioStatsSnapshot;
// ============================================================================
// GLOBAL STATISTICS + STATISTICS TRACKER
// ============================================================================
pub static MMIO_STATS: MmioStats = MmioStats::new();
pub struct MmioStats {
    total_regions: AtomicUsize,
    total_mapped_size: AtomicU64,
    read_operations: AtomicU64,
    write_operations: AtomicU64,
    next_region_id: AtomicU64,
}

impl MmioStats {
    pub const fn new() -> Self {
        Self {
            total_regions: AtomicUsize::new(0),
            total_mapped_size: AtomicU64::new(0),
            read_operations: AtomicU64::new(0),
            write_operations: AtomicU64::new(0),
            next_region_id: AtomicU64::new(1),
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_region_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_mapping(&self, size: usize) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_unmapping(&self, size: usize) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        self.total_mapped_size.fetch_sub(size as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_read(&self) {
        self.read_operations.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_write(&self) {
        self.write_operations.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn total_regions(&self) -> usize {
        self.total_regions.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn total_mapped_size(&self) -> u64 {
        self.total_mapped_size.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn read_operations(&self) -> u64 {
        self.read_operations.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn write_operations(&self) -> u64 {
        self.write_operations.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> MmioStatsSnapshot {
        MmioStatsSnapshot {
            total_regions: self.total_regions(),
            total_mapped_size: self.total_mapped_size(),
            read_operations: self.read_operations(),
            write_operations: self.write_operations(),
        }
    }
}

// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::super::error::{RegionError, RegionResult};
use super::super::stats::RegionStatistics;
use super::super::types::{MemRegion, RegionFlags, RegionStats, RegionType};
use super::core::RegionManager;
use alloc::vec::Vec;

impl RegionManager {
    pub fn find_region_by_address(&self, addr: u64) -> Option<&MemRegion> {
        self.regions.values().find(|r| r.contains(addr))
    }

    pub fn find_regions_by_type(&self, region_type: RegionType) -> Vec<MemRegion> {
        self.region_pools.get(&region_type).cloned().unwrap_or_default()
    }

    pub fn has_overlap(&self, region: &MemRegion) -> bool {
        self.regions.values().any(|r| r.overlaps(region))
    }

    pub fn get_fragmentation_info(&self) -> (usize, u64) {
        (
            self.free_regions.len(),
            self.free_regions.iter().map(|r| r.size as u64).max().unwrap_or(0),
        )
    }

    pub fn protect_region(&mut self, region_id: u64, flags: RegionFlags) -> RegionResult<()> {
        self.regions.get_mut(&region_id).ok_or(RegionError::NotFound)?.set_flag(flags);
        Ok(())
    }

    pub fn get_stats(&self, stats: &RegionStatistics) -> RegionStats {
        let (fragment_count, largest_free) = self.get_fragmentation_info();
        RegionStats {
            total_regions: self.regions.len(),
            free_regions: self.free_regions.len(),
            allocated_bytes: stats.allocated_bytes(),
            free_bytes: stats.free_bytes(),
            allocation_count: stats.allocation_count(),
            deallocation_count: stats.deallocation_count(),
            merge_count: stats.merge_count(),
            split_count: stats.split_count(),
            fragment_count,
            largest_free_block: largest_free,
        }
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
    pub fn free_region_count(&self) -> usize {
        self.free_regions.len()
    }
}

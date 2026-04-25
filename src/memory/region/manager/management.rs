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
use super::super::constants::align_size;
use super::super::error::{RegionError, RegionResult};
use super::super::stats::RegionStatistics;
use super::super::types::{get_timestamp, MemRegion, RegionType};
use super::core::RegionManager;
use alloc::vec::Vec;

impl RegionManager {
    pub fn add_region(
        &mut self,
        mut region: MemRegion,
        stats: &RegionStatistics,
    ) -> RegionResult<u64> {
        let region_id = self.next_region_id;
        self.next_region_id += 1;
        region.creation_time = get_timestamp();
        if self.has_overlap(&region) {
            return Err(RegionError::Overlapping);
        }
        let is_free = region.region_type == RegionType::Available;
        stats.add_region(region.size as u64, is_free);
        self.regions.insert(region_id, region);
        if is_free {
            self.free_regions.push(region);
        }
        self.region_pools.entry(region.region_type).or_insert_with(Vec::new).push(region);
        Ok(region_id)
    }

    pub fn remove_region(
        &mut self,
        region_id: u64,
        stats: &RegionStatistics,
    ) -> RegionResult<MemRegion> {
        let region = self.regions.remove(&region_id).ok_or(RegionError::NotFound)?;
        let is_free = region.region_type == RegionType::Available;
        stats.remove_region(region.size as u64, is_free);
        if is_free {
            self.free_regions.retain(|r| r.start != region.start);
        }
        if let Some(pool) = self.region_pools.get_mut(&region.region_type) {
            pool.retain(|r| r.start != region.start);
        }
        Ok(region)
    }

    pub fn allocate_region(
        &mut self,
        size: usize,
        region_type: RegionType,
        align: u64,
        stats: &RegionStatistics,
    ) -> RegionResult<MemRegion> {
        let aligned_size = align_size(size, align as usize);
        for (i, region) in self.free_regions.iter().enumerate() {
            let aligned_start = (region.start + align - 1) & !(align - 1);
            let available_size = region.end().saturating_sub(aligned_start);
            if available_size >= aligned_size as u64 {
                let mut allocated = MemRegion::new(aligned_start, aligned_size, region_type);
                allocated.creation_time = get_timestamp();
                let remaining_region = *region;
                self.free_regions.remove(i);
                for fragment in remaining_region.subtract(&allocated).iter().flatten() {
                    self.free_regions.push(*fragment);
                }
                let region_id = self.next_region_id;
                self.next_region_id += 1;
                self.regions.insert(region_id, allocated);
                stats.record_allocation(aligned_size as u64);
                return Ok(allocated);
            }
        }
        Err(RegionError::NoFreeRegion)
    }

    pub fn deallocate_region(
        &mut self,
        region: MemRegion,
        stats: &RegionStatistics,
    ) -> RegionResult<()> {
        self.free_regions.push(MemRegion::new(region.start, region.size, RegionType::Available));
        self.merge_adjacent_free_regions(stats);
        stats.record_deallocation(region.size as u64);
        Ok(())
    }
}

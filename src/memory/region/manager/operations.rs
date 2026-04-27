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
use super::super::types::MemRegion;
use super::core::RegionManager;
use alloc::vec::Vec;

impl RegionManager {
    pub fn merge_adjacent_free_regions(&mut self, stats: &RegionStatistics) {
        self.free_regions.sort_by_key(|r| r.start);
        let mut merged_regions = Vec::new();
        let mut current_region: Option<MemRegion> = None;
        for region in self.free_regions.drain(..) {
            match current_region.as_mut() {
                Some(current) => {
                    if let Some(merged) = current.union(&region) {
                        *current = merged;
                        stats.record_merge();
                    } else {
                        merged_regions.push(*current);
                        *current = region;
                    }
                }
                None => {
                    current_region = Some(region);
                }
            }
        }
        if let Some(region) = current_region {
            merged_regions.push(region);
        }
        self.free_regions = merged_regions;
    }

    pub fn split_region(
        &mut self,
        region_id: u64,
        offset: usize,
        stats: &RegionStatistics,
    ) -> RegionResult<(MemRegion, MemRegion)> {
        let region = self.regions.get(&region_id).ok_or(RegionError::NotFound)?.clone();
        if offset >= region.size {
            return Err(RegionError::InvalidSplitOffset);
        }
        let first_part = MemRegion::new(region.start, offset, region.region_type);
        let second_part =
            MemRegion::new(region.start + offset as u64, region.size - offset, region.region_type);
        self.regions.remove(&region_id);
        let first_id = self.next_region_id;
        self.next_region_id += 1;
        let second_id = self.next_region_id;
        self.next_region_id += 1;
        self.regions.insert(first_id, first_part);
        self.regions.insert(second_id, second_part);
        stats.record_split();
        Ok((first_part, second_part))
    }
}

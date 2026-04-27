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

#[derive(Debug, Clone, Default)]
pub struct RegionStats {
    pub total_regions: usize,
    pub free_regions: usize,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub allocation_count: u64,
    pub deallocation_count: u64,
    pub merge_count: u64,
    pub split_count: u64,
    pub fragment_count: usize,
    pub largest_free_block: u64,
}

impl RegionStats {
    pub const fn new() -> Self {
        Self {
            total_regions: 0,
            free_regions: 0,
            allocated_bytes: 0,
            free_bytes: 0,
            allocation_count: 0,
            deallocation_count: 0,
            merge_count: 0,
            split_count: 0,
            fragment_count: 0,
            largest_free_block: 0,
        }
    }
    pub const fn total_memory(&self) -> u64 {
        self.allocated_bytes + self.free_bytes
    }
    pub fn fragmentation_ratio(&self) -> f64 {
        if self.free_bytes == 0 {
            return 0.0;
        }
        1.0 - (self.largest_free_block as f64 / self.free_bytes as f64)
    }
}

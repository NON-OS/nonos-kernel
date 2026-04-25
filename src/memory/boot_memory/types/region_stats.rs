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

#[derive(Debug, Default, Clone, Copy)]
pub struct RegionStats {
    pub total_memory: u64,
    pub available_memory: u64,
    pub allocated_memory: u64,
    pub reserved_memory: u64,
    pub kernel_memory: u64,
    pub capsule_memory: u64,
    pub hardware_memory: u64,
    pub defective_memory: u64,
    pub region_count: usize,
}

impl RegionStats {
    #[inline]
    pub const fn free_memory(&self) -> u64 {
        if self.available_memory > self.allocated_memory {
            self.available_memory - self.allocated_memory
        } else {
            0
        }
    }

    #[inline]
    pub fn allocation_percent(&self) -> f64 {
        if self.available_memory == 0 {
            0.0
        } else {
            (self.allocated_memory as f64 / self.available_memory as f64) * 100.0
        }
    }
}

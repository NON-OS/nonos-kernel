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

#[derive(Debug, Clone, Copy)]
pub struct ManagerStats {
    pub total_regions: usize,
    pub allocated_memory: u64,
    pub peak_memory: u64,
    pub allocations: u64,
    pub deallocations: u64,
}

impl ManagerStats {
    #[inline]
    pub fn utilization_percent(&self) -> f64 {
        if self.peak_memory == 0 {
            0.0
        } else {
            (self.allocated_memory as f64 / self.peak_memory as f64) * 100.0
        }
    }
}

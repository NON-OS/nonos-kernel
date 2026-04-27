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

use super::super::types::{RegionStats, RegionType};
use super::state::BootMemoryManager;

impl BootMemoryManager {
    pub(super) fn get_region_stats(&self) -> RegionStats {
        let mut stats = RegionStats::default();
        for region in &self.regions {
            let size = region.size();
            stats.total_memory = stats.total_memory.saturating_add(size);
            match region.region_type {
                RegionType::Available => {
                    stats.available_memory = stats.available_memory.saturating_add(size)
                }
                RegionType::Reserved => {
                    stats.reserved_memory = stats.reserved_memory.saturating_add(size)
                }
                RegionType::Kernel => {
                    stats.kernel_memory = stats.kernel_memory.saturating_add(size)
                }
                RegionType::Capsule => {
                    stats.capsule_memory = stats.capsule_memory.saturating_add(size)
                }
                RegionType::Hardware => {
                    stats.hardware_memory = stats.hardware_memory.saturating_add(size)
                }
                RegionType::Defective => {
                    stats.defective_memory = stats.defective_memory.saturating_add(size)
                }
            }
        }
        stats.allocated_memory = self.allocated_size;
        stats.region_count = self.regions.len();
        stats
    }
}

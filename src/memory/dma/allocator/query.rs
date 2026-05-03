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
use super::super::types::{DmaRegion, StreamingMapping};
use super::core::DmaAllocator;
use crate::memory::addr::{PhysAddr, VirtAddr};
use alloc::vec::Vec;

impl DmaAllocator {
    pub fn get_mapping_info(&self, mapping_id: u64) -> Option<StreamingMapping> {
        self.streaming_mappings.get(&mapping_id).copied()
    }

    pub fn get_region_info(&self, virt_addr: VirtAddr) -> Option<DmaRegion> {
        self.coherent_regions.get(&virt_addr).copied()
    }

    pub fn is_dma_region(&self, virt_addr: VirtAddr) -> bool {
        self.coherent_regions.contains_key(&virt_addr)
            || self
                .streaming_mappings
                .values()
                .any(|m| m.bounce_buffer.map(|b| b.virt_addr == virt_addr).unwrap_or(false))
    }

    pub fn get_allocated_regions(&self) -> Vec<DmaRegion> {
        self.coherent_regions.values().copied().collect()
    }

    pub fn find_by_phys_addr(&self, phys_addr: PhysAddr) -> Option<VirtAddr> {
        for (virt, region) in self.coherent_regions.iter() {
            if region.phys_addr == phys_addr {
                return Some(*virt);
            }
        }
        None
    }
}

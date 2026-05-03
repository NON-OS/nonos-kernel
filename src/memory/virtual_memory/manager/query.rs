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
use super::super::stats::VirtualMemoryStatistics;
use super::super::types::{VmArea, VmStats};
use super::core::VirtualMemoryManager;
use crate::memory::addr::VirtAddr;
use alloc::vec::Vec;

impl VirtualMemoryManager {
    pub fn find_vm_area_by_address(&self, addr: VirtAddr) -> Option<&VmArea> {
        self.vm_areas.values().find(|area| area.contains(addr))
    }

    pub(super) fn find_vm_area_id_by_address(&self, addr: VirtAddr) -> Option<u64> {
        self.vm_areas.iter().find(|(_, area)| area.contains(addr)).map(|(&id, _)| id)
    }

    pub fn has_overlap(&self, vm_area: &VmArea) -> bool {
        self.vm_areas.values().any(|area| area.overlaps(vm_area))
    }

    pub fn merge_adjacent_areas(&mut self) {
        let mut areas_to_merge = Vec::new();
        let mut areas: Vec<_> = self.vm_areas.iter().collect();
        areas.sort_by_key(|(_, area)| area.start.as_u64());
        for window in areas.windows(2) {
            let (id1, area1) = window[0];
            let (id2, area2) = window[1];
            if area1.can_merge(area2) {
                areas_to_merge.push((*id1, *id2));
            }
        }
        for (id1, id2) in areas_to_merge {
            if let (Some(area1), Some(area2)) = (self.vm_areas.get(&id1), self.vm_areas.get(&id2)) {
                let merged_start = area1.start.min(area2.start);
                let merged_end = area1.end().max(area2.end());
                let merged_size = (merged_end.as_u64() - merged_start.as_u64()) as usize;
                let merged_area =
                    VmArea::new(merged_start, merged_size, area1.protection, area1.vm_type);
                self.vm_areas.remove(&id1);
                self.vm_areas.remove(&id2);
                self.vm_areas.insert(id1, merged_area);
            }
        }
    }

    pub fn get_vm_stats(&self, stats: &VirtualMemoryStatistics) -> VmStats {
        VmStats {
            total_vm_areas: self.vm_areas.len(),
            address_spaces: self.address_spaces.len(),
            total_virtual_memory: stats.total_virtual_memory(),
            heap_usage: stats.heap_usage(),
            stack_usage: stats.stack_usage(),
            mmap_usage: stats.mmap_usage(),
            page_faults: stats.page_faults(),
            protection_faults: stats.protection_faults(),
            swap_operations: stats.swap_operations(),
            tlb_shootdowns: stats.tlb_shootdowns(),
        }
    }
}

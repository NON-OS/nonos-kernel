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

use super::super::stats::VirtualMemoryStatistics;
use super::super::types::{VmArea, VmProtection};
use super::core::VirtualMemoryManager;
use super::utils::protection_to_page_permissions;
use crate::memory::{frame_alloc, layout, paging};
use x86_64::VirtAddr;

impl VirtualMemoryManager {
    pub fn map_vm_area(
        &mut self,
        vm_area: VmArea,
        stats: &VirtualMemoryStatistics,
    ) -> Result<u64, &'static str> {
        if !self.initialized {
            return Err("Virtual memory manager not initialized");
        }
        if self.has_overlap(&vm_area) {
            return Err("VM area overlaps with existing area");
        }
        let area_id = self.next_area_id;
        self.next_area_id += 1;
        let page_permissions = protection_to_page_permissions(vm_area.protection);
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        for i in 0..page_count {
            let va = VirtAddr::new(vm_area.start.as_u64() + (i * layout::PAGE_SIZE) as u64);
            if vm_area.vm_type.is_demand_paged() {
                let pa =
                    frame_alloc::allocate_frame().ok_or("Failed to allocate physical frame")?;
                paging::map_page(va, pa, page_permissions).map_err(|_| "Failed to map page")?;
                unsafe {
                    core::ptr::write_bytes(
                        (layout::DIRECTMAP_BASE + pa.as_u64()) as *mut u8,
                        0,
                        layout::PAGE_SIZE,
                    );
                }
            }
        }
        stats.record_vm_area(vm_area.size as u64, vm_area.vm_type);
        self.vm_areas.insert(area_id, vm_area);
        if let Some(address_space) = self.address_spaces.get_mut(&self.current_asid) {
            address_space.vm_areas.push(area_id);
        }
        Ok(area_id)
    }

    pub fn unmap_vm_area(
        &mut self,
        area_id: u64,
        stats: &VirtualMemoryStatistics,
    ) -> Result<(), &'static str> {
        let vm_area = self.vm_areas.remove(&area_id).ok_or("VM area not found")?;
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        for i in 0..page_count {
            let va = VirtAddr::new(vm_area.start.as_u64() + (i * layout::PAGE_SIZE) as u64);
            if let Ok(pa) = paging::unmap_page(va) {
                let _ = frame_alloc::deallocate_frame(pa);
            }
        }
        if let Some(address_space) = self.address_spaces.get_mut(&self.current_asid) {
            address_space.vm_areas.retain(|&id| id != area_id);
        }
        stats.record_vm_area_removal(vm_area.size as u64, vm_area.vm_type);
        Ok(())
    }

    pub fn protect_vm_area(
        &mut self,
        area_id: u64,
        new_protection: VmProtection,
    ) -> Result<(), &'static str> {
        let vm_area = self.vm_areas.get_mut(&area_id).ok_or("VM area not found")?;
        vm_area.protection = new_protection;
        let page_permissions = protection_to_page_permissions(new_protection);
        let page_count = (vm_area.size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        paging::protect_pages(vm_area.start, page_count, page_permissions)
            .map_err(|_| "Failed to protect pages")?;
        Ok(())
    }
}

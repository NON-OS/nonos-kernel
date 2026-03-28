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

use x86_64::{PhysAddr, VirtAddr};
use super::super::constants::*;
use super::super::error::{MmuError, MmuResult};
use super::super::types::PagePermissions;
use super::core::MMU;

impl MMU {
    pub fn map_kernel_range(&self, virt_start: VirtAddr, phys_start: PhysAddr, size: usize, permissions: PagePermissions) -> MmuResult<()> {
        if !self.is_initialized() { return Err(MmuError::NotInitialized); }
        let cr3 = self.get_current_cr3();
        if cr3 == 0 { return Err(MmuError::NoPageTableLoaded); }
        let pml4_virt = self.frame_to_virt(PhysAddr::new(cr3));
        self.map_memory_range(pml4_virt, virt_start, phys_start, size, permissions)
    }

    pub(super) fn map_memory_range(&self, pml4_virt: VirtAddr, virt_start: VirtAddr, phys_start: PhysAddr, size: usize, permissions: PagePermissions) -> MmuResult<()> {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(virt_start.as_u64() + (i * PAGE_SIZE) as u64);
            let pa = PhysAddr::new(phys_start.as_u64() + (i * PAGE_SIZE) as u64);
            self.map_single_page(pml4_virt, va, pa, permissions)?;
        }
        Ok(())
    }

    pub(super) fn map_single_page(&self, pml4_virt: VirtAddr, virt_addr: VirtAddr, phys_addr: PhysAddr, permissions: PagePermissions) -> MmuResult<()> {
        if permissions.is_wx_violation() { return Err(MmuError::WXViolation); }
        let pml4_idx = pml4_index(virt_addr.as_u64());
        let pdpt_idx = pdpt_index(virt_addr.as_u64());
        let pd_idx = pd_index(virt_addr.as_u64());
        let pt_idx = pt_index(virt_addr.as_u64());
        unsafe {
            let pml4_table = pml4_virt.as_mut_ptr::<u64>();
            let pml4_entry_ptr = pml4_table.add(pml4_idx);
            let pdpt_phys = if !pte_is_present(*pml4_entry_ptr) {
                let f = self.allocate_page_table_frame()?;
                core::ptr::write_bytes(self.frame_to_virt(f).as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
                *pml4_entry_ptr = f.as_u64() | PTE_PRESENT | PTE_WRITABLE;
                f
            } else { PhysAddr::new(pte_address(*pml4_entry_ptr)) };
            let pdpt_virt = self.frame_to_virt(pdpt_phys);
            let pdpt_entry_ptr = pdpt_virt.as_mut_ptr::<u64>().add(pdpt_idx);
            let pd_phys = if !pte_is_present(*pdpt_entry_ptr) {
                let f = self.allocate_page_table_frame()?;
                core::ptr::write_bytes(self.frame_to_virt(f).as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
                *pdpt_entry_ptr = f.as_u64() | PTE_PRESENT | PTE_WRITABLE;
                f
            } else { PhysAddr::new(pte_address(*pdpt_entry_ptr)) };
            let pd_virt = self.frame_to_virt(pd_phys);
            let pd_entry_ptr = pd_virt.as_mut_ptr::<u64>().add(pd_idx);
            let pt_phys = if !pte_is_present(*pd_entry_ptr) {
                let f = self.allocate_page_table_frame()?;
                core::ptr::write_bytes(self.frame_to_virt(f).as_mut_ptr::<u64>(), 0, PAGE_TABLE_ENTRIES);
                *pd_entry_ptr = f.as_u64() | PTE_PRESENT | PTE_WRITABLE;
                f
            } else { PhysAddr::new(pte_address(*pd_entry_ptr)) };
            let pt_virt = self.frame_to_virt(pt_phys);
            *pt_virt.as_mut_ptr::<u64>().add(pt_idx) = permissions.to_pte(phys_addr.as_u64()).to_raw();
        }
        self.page_tables.lock().insert(virt_addr.as_u64(), permissions.to_pte(phys_addr.as_u64()));
        Ok(())
    }
}

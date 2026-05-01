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

use super::super::constants::*;
use super::super::error::{MmuError, MmuResult};
use super::super::types::PagePermissions;
use super::core::MMU;
use crate::memory::addr::{PhysAddr, VirtAddr};

impl MMU {
    pub fn change_page_protection(
        &self,
        virt_addr: VirtAddr,
        new_permissions: PagePermissions,
    ) -> MmuResult<()> {
        if new_permissions.is_wx_violation() {
            return Err(MmuError::WXViolation);
        }
        let cr3 = self.get_current_cr3();
        if cr3 == 0 {
            return Err(MmuError::NoPageTableLoaded);
        }
        let pml4_virt = self.frame_to_virt(PhysAddr::new(cr3));
        self.update_page_entry(pml4_virt, virt_addr, new_permissions)?;
        self.invalidate_tlb_page(virt_addr);
        Ok(())
    }

    pub(super) fn update_page_entry(
        &self,
        pml4_virt: VirtAddr,
        virt_addr: VirtAddr,
        permissions: PagePermissions,
    ) -> MmuResult<()> {
        if permissions.is_wx_violation() {
            return Err(MmuError::WXViolation);
        }
        let pml4_idx = pml4_index(virt_addr.as_u64());
        let pdpt_idx = pdpt_index(virt_addr.as_u64());
        let pd_idx = pd_index(virt_addr.as_u64());
        let pt_idx = pt_index(virt_addr.as_u64());
        unsafe {
            let pml4_entry = *pml4_virt.as_ptr::<u64>().add(pml4_idx);
            if !pte_is_present(pml4_entry) {
                return Err(MmuError::NotMapped);
            }
            let pdpt_virt = self.frame_to_virt(PhysAddr::new(pte_address(pml4_entry)));
            let pdpt_entry = *pdpt_virt.as_ptr::<u64>().add(pdpt_idx);
            if !pte_is_present(pdpt_entry) {
                return Err(MmuError::NotMapped);
            }
            let pd_virt = self.frame_to_virt(PhysAddr::new(pte_address(pdpt_entry)));
            let pd_entry = *pd_virt.as_ptr::<u64>().add(pd_idx);
            if !pte_is_present(pd_entry) {
                return Err(MmuError::NotMapped);
            }
            let pt_virt = self.frame_to_virt(PhysAddr::new(pte_address(pd_entry)));
            let pt_entry_ptr = pt_virt.as_mut_ptr::<u64>().add(pt_idx);
            let old_entry = *pt_entry_ptr;
            if !pte_is_present(old_entry) {
                return Err(MmuError::NotMapped);
            }
            *pt_entry_ptr = permissions.to_pte(pte_address(old_entry)).to_raw();
        }
        Ok(())
    }
}

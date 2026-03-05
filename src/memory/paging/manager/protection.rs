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

use x86_64::{PhysAddr, VirtAddr};

use super::core::PagingManager;
use crate::memory::paging::constants::*;
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::stats::PagingStatistics;
use crate::memory::paging::tlb;
use crate::memory::paging::types::{get_timestamp, PagePermissions};
use crate::memory::layout;

impl PagingManager {
    pub fn update_page_flags(
        &mut self,
        virtual_addr: VirtAddr,
        new_permissions: PagePermissions,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        if new_permissions.is_wx_violation() {
            return Err(PagingError::WXViolation);
        }

        let page_addr = page_align_down(virtual_addr.as_u64());

        let mapping = self
            .mappings
            .get_mut(&page_addr)
            .ok_or(PagingError::PageNotMapped)?;

        mapping.permissions = new_permissions;
        mapping.last_accessed = get_timestamp();

        let pte_flags = new_permissions.to_pte_flags();
        self.update_pte(virtual_addr, pte_flags)?;

        tlb::invalidate_page(virtual_addr);
        stats.record_modification();

        Ok(())
    }

    fn update_pte(&self, va: VirtAddr, new_flags: u64) -> PagingResult<()> {
        let va_val = va.as_u64();
        let l4_idx = pml4_index(va_val);
        let l3_idx = pdpt_index(va_val);
        let l2_idx = pd_index(va_val);
        let l1_idx = pt_index(va_val);

        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;

        // SAFETY: Walking page tables with validation
        unsafe {
            let l4_table =
                &*((layout::DIRECTMAP_BASE + cr3.as_u64()) as *const [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l4_table[l4_idx]) {
                return Err(PagingError::Pml4NotPresent);
            }

            let l3_pa = PhysAddr::new(pte_address(l4_table[l4_idx]));
            let l3_table = &mut *((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l3_table[l3_idx]) {
                return Err(PagingError::PdptNotPresent);
            }

            if pte_is_huge(l3_table[l3_idx]) {
                let phys_addr = pte_address(l3_table[l3_idx]);
                l3_table[l3_idx] = phys_addr | new_flags | PTE_HUGE_PAGE;
                return Ok(());
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &mut *((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l2_table[l2_idx]) {
                return Err(PagingError::PdNotPresent);
            }

            if pte_is_huge(l2_table[l2_idx]) {
                let phys_addr = pte_address(l2_table[l2_idx]);
                l2_table[l2_idx] = phys_addr | new_flags | PTE_HUGE_PAGE;
                return Ok(());
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l1_table[l1_idx]) {
                return Err(PagingError::PtNotPresent);
            }

            let phys_addr = pte_address(l1_table[l1_idx]);
            l1_table[l1_idx] = phys_addr | new_flags;
        }

        Ok(())
    }
}

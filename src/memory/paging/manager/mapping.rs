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
use crate::memory::paging::types::{PageMapping, PagePermissions, PageSize};
use crate::memory::{frame_alloc, layout};

impl PagingManager {
    pub fn map_page(
        &mut self,
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        permissions: PagePermissions,
        size: PageSize,
        stats: &PagingStatistics,
    ) -> PagingResult<()> {
        if !self.initialized {
            return Err(PagingError::NotInitialized);
        }

        if permissions.is_wx_violation() {
            return Err(PagingError::WXViolation);
        }

        let pte_flags = permissions.to_pte_flags();
        self.install_mapping(virtual_addr, physical_addr, pte_flags)?;

        let mapping = PageMapping::new(virtual_addr, physical_addr, size, permissions);
        let page_addr = page_align_down(virtual_addr.as_u64());
        self.mappings.insert(page_addr, mapping);

        stats.record_mapping(permissions, size);

        Ok(())
    }

    fn install_mapping(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        flags: u64,
    ) -> PagingResult<()> {
        let va_val = va.as_u64();
        let l4_idx = pml4_index(va_val);
        let l3_idx = pdpt_index(va_val);
        let l2_idx = pd_index(va_val);
        let l1_idx = pt_index(va_val);

        let cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;

        // SAFETY: Walking and modifying page tables with proper validation
        unsafe {
            let l4_table =
                &mut *((layout::DIRECTMAP_BASE + cr3.as_u64()) as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l4_table[l4_idx]) {
                let new_table =
                    frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
                l4_table[l4_idx] = new_table.as_u64() | PTE_TABLE_FLAGS;
                let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
                core::ptr::write_bytes(table_va as *mut u8, 0, PAGE_SIZE_4K);
            }

            let l3_pa = PhysAddr::new(pte_address(l4_table[l4_idx]));
            let l3_table = &mut *((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l3_table[l3_idx]) {
                let new_table =
                    frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
                l3_table[l3_idx] = new_table.as_u64() | PTE_TABLE_FLAGS;
                let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
                core::ptr::write_bytes(table_va as *mut u8, 0, PAGE_SIZE_4K);
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &mut *((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l2_table[l2_idx]) {
                let new_table =
                    frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
                l2_table[l2_idx] = new_table.as_u64() | PTE_TABLE_FLAGS;
                let table_va = layout::DIRECTMAP_BASE + new_table.as_u64();
                core::ptr::write_bytes(table_va as *mut u8, 0, PAGE_SIZE_4K);
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            l1_table[l1_idx] = pa.as_u64() | flags;
        }

        tlb::invalidate_page(va);

        Ok(())
    }

    pub fn unmap_page(
        &mut self,
        virtual_addr: VirtAddr,
    ) -> PagingResult<(PhysAddr, PagePermissions, PageSize)> {
        if !self.initialized {
            return Err(PagingError::NotInitialized);
        }

        let page_addr = page_align_down(virtual_addr.as_u64());

        let mapping = self
            .mappings
            .remove(&page_addr)
            .ok_or(PagingError::PageNotMapped)?;

        let physical_addr = self.remove_mapping(virtual_addr)?;

        Ok((physical_addr, mapping.permissions, mapping.size))
    }

    fn remove_mapping(&self, va: VirtAddr) -> PagingResult<PhysAddr> {
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
            let l3_table = &*((layout::DIRECTMAP_BASE + l3_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l3_table[l3_idx]) {
                return Err(PagingError::PdptNotPresent);
            }

            let l2_pa = PhysAddr::new(pte_address(l3_table[l3_idx]));
            let l2_table = &*((layout::DIRECTMAP_BASE + l2_pa.as_u64())
                as *const [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l2_table[l2_idx]) {
                return Err(PagingError::PdNotPresent);
            }

            let l1_pa = PhysAddr::new(pte_address(l2_table[l2_idx]));
            let l1_table = &mut *((layout::DIRECTMAP_BASE + l1_pa.as_u64())
                as *mut [u64; PAGE_TABLE_ENTRIES]);

            if !pte_is_present(l1_table[l1_idx]) {
                return Err(PagingError::PtNotPresent);
            }

            let physical_addr = PhysAddr::new(pte_address(l1_table[l1_idx]));
            l1_table[l1_idx] = 0;

            tlb::invalidate_page(va);

            Ok(physical_addr)
        }
    }
}

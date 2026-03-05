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

use x86_64::PhysAddr;

use super::core::PagingManager;
use crate::memory::paging::constants::{KERNEL_ASID, KERNEL_PML4_START, PAGE_TABLE_ENTRIES};
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::types::AddressSpace;
use crate::memory::{frame_alloc, layout};

impl PagingManager {
    pub(crate) fn create_kernel_address_space(&mut self) -> PagingResult<()> {
        let cr3_value = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        let kernel_space = AddressSpace::new(KERNEL_ASID, cr3_value, 0);
        self.address_spaces.insert(KERNEL_ASID, kernel_space);
        Ok(())
    }

    pub fn create_address_space(&mut self, process_id: u32) -> PagingResult<u32> {
        let asid = self.next_asid;
        self.next_asid = self.next_asid.wrapping_add(1);

        let page_table_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;

        let address_space = AddressSpace::new(asid, page_table_frame, process_id);
        self.address_spaces.insert(asid, address_space);

        self.initialize_address_space(page_table_frame)?;

        Ok(asid)
    }

    fn initialize_address_space(&self, page_table_pa: PhysAddr) -> PagingResult<()> {
        let page_table_va = layout::DIRECTMAP_BASE + page_table_pa.as_u64();

        // SAFETY: We just allocated this frame and will initialize it
        let page_table = unsafe { &mut *(page_table_va as *mut [u64; PAGE_TABLE_ENTRIES]) };

        for entry in page_table.iter_mut() {
            *entry = 0;
        }

        if let Some(kernel_cr3) = self.active_page_table {
            let kernel_table_va = layout::DIRECTMAP_BASE + kernel_cr3.as_u64();
            // SAFETY: Reading from valid kernel page table
            let kernel_table =
                unsafe { &*(kernel_table_va as *const [u64; PAGE_TABLE_ENTRIES]) };

            for i in KERNEL_PML4_START..PAGE_TABLE_ENTRIES {
                page_table[i] = kernel_table[i];
            }
        }

        Ok(())
    }

    pub fn switch_address_space(&mut self, asid: u32) -> PagingResult<()> {
        let address_space = self
            .address_spaces
            .get(&asid)
            .ok_or(PagingError::AddressSpaceNotFound)?;

        // SAFETY: Loading valid page table into CR3
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) address_space.cr3_value.as_u64(),
                options(nostack, preserves_flags)
            );
        }

        self.active_page_table = Some(address_space.cr3_value);
        Ok(())
    }

    pub fn cleanup_address_space(&mut self, asid: u32) -> PagingResult<()> {
        if let Some(address_space) = self.address_spaces.remove(&asid) {
            for mapping_addr in &address_space.mappings {
                let _ = self.unmap_page(*mapping_addr);
            }

            let _ = frame_alloc::deallocate_frame(address_space.cr3_value);
        }

        Ok(())
    }
}

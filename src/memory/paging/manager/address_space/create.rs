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

use super::super::core::PagingManager;
use crate::memory::addr::PhysAddr;
use crate::memory::frame_alloc;
use crate::memory::paging::constants::{KERNEL_ASID, PAGE_TABLE_ENTRIES};
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::types::AddressSpace;
use crate::memory::unified::phys_to_virt;

// PML4 split: entries 256..511 are the kernel half (the directmap PML4
// entry at index 486 lives here, along with kernel text/data/heap);
// entries 0..255 are the per-process user half and start empty for
// every fresh address space.
const PML4_KERNEL_HALF_START: usize = PAGE_TABLE_ENTRIES / 2;

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
        let page_table_va = phys_to_virt(page_table_pa);
        let page_table =
            unsafe { &mut *(page_table_va.as_u64() as *mut [u64; PAGE_TABLE_ENTRIES]) };
        for entry in page_table.iter_mut() {
            *entry = 0;
        }
        // Kernel-half PML4 entries are global state shared across every
        // address space; the user half stays zero so a fresh AS carries
        // no inherited user mappings. Capsule ELF segments are mapped
        // into the new AS by `spawn_*_capsule` after switching CR3 to
        // it, never via this clone.
        let kernel_cr3 = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        let kernel_table_va = phys_to_virt(kernel_cr3);
        let kernel_table =
            unsafe { &*(kernel_table_va.as_u64() as *const [u64; PAGE_TABLE_ENTRIES]) };
        let mut populated = 0usize;
        for i in PML4_KERNEL_HALF_START..PAGE_TABLE_ENTRIES {
            page_table[i] = kernel_table[i];
            if kernel_table[i] != 0 {
                populated += 1;
            }
        }
        if populated == 0 {
            return Err(PagingError::NoActivePageTable);
        }
        Ok(())
    }
}

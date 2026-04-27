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
use crate::memory::paging::constants::{KERNEL_ASID, PAGE_TABLE_ENTRIES};
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::types::AddressSpace;
use crate::memory::frame_alloc;
use x86_64::PhysAddr;

fn phys_to_virt(phys: u64) -> u64 {
    phys
}

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
        let page_table_va = phys_to_virt(page_table_pa.as_u64());
        let page_table = unsafe { &mut *(page_table_va as *mut [u64; PAGE_TABLE_ENTRIES]) };
        for entry in page_table.iter_mut() {
            *entry = 0;
        }
        if let Some(kernel_cr3) = self.active_page_table {
            let kernel_table_va = phys_to_virt(kernel_cr3.as_u64());
            let kernel_table = unsafe { &*(kernel_table_va as *const [u64; PAGE_TABLE_ENTRIES]) };
            for i in 0..PAGE_TABLE_ENTRIES {
                page_table[i] = kernel_table[i];
            }
        }
        Ok(())
    }
}

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
use super::kernel_half::seed_kernel_half_pdpts;
use crate::memory::frame_alloc;
use crate::memory::paging::constants::KERNEL_ASID;
use crate::memory::paging::error::{PagingError, PagingResult};
use crate::memory::paging::types::AddressSpace;

impl PagingManager {
    // Register the kernel CR3 as KERNEL_ASID and seed every empty
    // kernel-half PML4 entry with a fresh PDPT. Every later
    // `create_address_space` clone shares those PDPT pointers, so
    // any kernel-half allocation that lands later writes into the
    // shared sub-tree and propagates to all address spaces.
    pub(crate) fn create_kernel_address_space(&mut self) -> PagingResult<()> {
        let cr3_value = self.active_page_table.ok_or(PagingError::NoActivePageTable)?;
        let kernel_space = AddressSpace::new(KERNEL_ASID, cr3_value, 0);
        self.address_spaces.insert(KERNEL_ASID, kernel_space);
        seed_kernel_half_pdpts(cr3_value)
    }

    // Allocate a fresh PML4 frame, register a new asid, and clone
    // the kernel half from KERNEL_ASID. The user half stays empty.
    pub fn create_address_space(&mut self, process_id: u32) -> PagingResult<u32> {
        let asid = self.next_asid;
        self.next_asid = self.next_asid.wrapping_add(1);
        let page_table_frame =
            frame_alloc::allocate_frame().ok_or(PagingError::FrameAllocationFailed)?;
        let address_space = AddressSpace::new(asid, page_table_frame, process_id);
        self.address_spaces.insert(asid, address_space);
        self.clone_kernel_half_into(page_table_frame)?;
        Ok(asid)
    }
}

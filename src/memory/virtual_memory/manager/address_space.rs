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
use super::super::constants::*;
use super::super::types::AddressSpace;
use super::core::VirtualMemoryManager;
use super::utils::get_timestamp;
use crate::memory::paging;
use alloc::vec::Vec;
use x86_64::VirtAddr;

impl VirtualMemoryManager {
    pub fn create_address_space(&mut self, process_id: u32) -> Result<u32, &'static str> {
        let asid = paging::create_address_space(process_id)
            .map_err(|_| "Failed to create address space")?;
        let page_table = paging::get_current_cr3();
        let address_space = AddressSpace {
            asid,
            page_table,
            vm_areas: Vec::new(),
            heap_start: VirtAddr::new(USER_HEAP_START),
            heap_end: VirtAddr::new(USER_HEAP_START),
            stack_start: VirtAddr::new(USER_STACK_BOTTOM),
            stack_end: VirtAddr::new(USER_STACK_TOP),
            mmap_start: VirtAddr::new(USER_MMAP_START),
            creation_time: get_timestamp(),
        };
        self.address_spaces.insert(asid, address_space);
        Ok(asid)
    }

    pub fn switch_address_space(&mut self, asid: u32) -> Result<(), &'static str> {
        if !self.address_spaces.contains_key(&asid) {
            return Err("Address space not found");
        }
        paging::switch_address_space(asid).map_err(|_| "Failed to switch address space")?;
        self.current_asid = asid;
        Ok(())
    }
}

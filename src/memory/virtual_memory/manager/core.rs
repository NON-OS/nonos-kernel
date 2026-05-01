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
use super::super::types::{AddressSpace, VmArea};
use super::utils::get_timestamp;
use crate::memory::{layout, paging};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use crate::memory::addr::VirtAddr;

pub struct VirtualMemoryManager {
    pub(super) vm_areas: BTreeMap<u64, VmArea>,
    pub(super) address_spaces: BTreeMap<u32, AddressSpace>,
    pub(super) next_area_id: u64,
    pub(super) current_asid: u32,
    pub(super) initialized: bool,
}

impl VirtualMemoryManager {
    pub const fn new() -> Self {
        Self {
            vm_areas: BTreeMap::new(),
            address_spaces: BTreeMap::new(),
            next_area_id: 1,
            current_asid: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }
        self.vm_areas.clear();
        self.address_spaces.clear();
        self.next_area_id = 1;
        self.create_kernel_address_space()?;
        self.initialized = true;
        Ok(())
    }

    fn create_kernel_address_space(&mut self) -> Result<(), &'static str> {
        let kernel_space = AddressSpace {
            asid: 0,
            page_table: paging::get_current_cr3(),
            vm_areas: Vec::new(),
            heap_start: VirtAddr::new(layout::KHEAP_BASE),
            heap_end: VirtAddr::new(layout::KHEAP_BASE + layout::KHEAP_SIZE),
            stack_start: VirtAddr::new(layout::KERNEL_BASE - layout::KSTACK_SIZE as u64),
            stack_end: VirtAddr::new(layout::KERNEL_BASE),
            mmap_start: VirtAddr::new(layout::VMAP_BASE),
            creation_time: get_timestamp(),
        };
        self.address_spaces.insert(0, kernel_space);
        self.current_asid = 0;
        Ok(())
    }
}

impl Default for VirtualMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

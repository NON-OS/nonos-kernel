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

extern crate alloc;
use super::helpers::get_timestamp;
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::paging::constants::KERNEL_ASID;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct AddressSpace {
    pub asid: u32,
    pub cr3_value: PhysAddr,
    pub mappings: Vec<VirtAddr>,
    pub process_id: u32,
    pub creation_time: u64,
}

impl AddressSpace {
    pub fn new(asid: u32, cr3_value: PhysAddr, process_id: u32) -> Self {
        Self { asid, cr3_value, mappings: Vec::new(), process_id, creation_time: get_timestamp() }
    }

    pub const fn is_kernel(&self) -> bool {
        self.asid == KERNEL_ASID
    }
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
    pub fn add_mapping(&mut self, va: VirtAddr) {
        self.mappings.push(va);
    }
    pub fn remove_mapping(&mut self, va: VirtAddr) {
        self.mappings.retain(|&addr| addr != va);
    }
}

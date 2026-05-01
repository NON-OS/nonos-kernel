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

use super::super::constants::INITIAL_REF_COUNT;
use super::flags::PageFlags;
use crate::memory::addr::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy)]
pub struct PageInfo {
    pub physical_addr: PhysAddr,
    pub virtual_addr: Option<VirtAddr>,
    pub flags: PageFlags,
    pub ref_count: u32,
    pub allocation_time: u64,
    pub last_access: u64,
}

impl PageInfo {
    pub fn new(physical_addr: PhysAddr, virtual_addr: Option<VirtAddr>, flags: PageFlags) -> Self {
        let now = super::super::manager::get_timestamp();
        Self {
            physical_addr,
            virtual_addr,
            flags,
            ref_count: INITIAL_REF_COUNT,
            allocation_time: now,
            last_access: now,
        }
    }

    pub fn is_mapped(&self) -> bool {
        self.virtual_addr.is_some()
    }
    pub fn is_dirty(&self) -> bool {
        self.flags.contains(PageFlags::DIRTY)
    }
    pub fn is_locked(&self) -> bool {
        self.flags.contains(PageFlags::LOCKED)
    }
}

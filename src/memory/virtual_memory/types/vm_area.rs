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

use super::helpers::get_timestamp;
use super::protection::VmProtection;
use super::vm_type::VmType;
use x86_64::VirtAddr;

#[derive(Debug, Clone)]
pub struct VmArea {
    pub start: VirtAddr,
    pub size: usize,
    pub protection: VmProtection,
    pub vm_type: VmType,
    pub flags: u32,
    pub creation_time: u64,
    pub access_count: u64,
    pub fault_count: u64,
}

impl VmArea {
    pub fn new(start: VirtAddr, size: usize, protection: VmProtection, vm_type: VmType) -> Self {
        Self {
            start,
            size,
            protection,
            vm_type,
            flags: 0,
            creation_time: get_timestamp(),
            access_count: 0,
            fault_count: 0,
        }
    }

    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.start.as_u64() + self.size as u64)
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end()
    }

    pub fn overlaps(&self, other: &VmArea) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    pub fn can_merge(&self, other: &VmArea) -> bool {
        self.protection == other.protection
            && self.vm_type == other.vm_type
            && (self.end() == other.start || other.end() == self.start)
    }
}

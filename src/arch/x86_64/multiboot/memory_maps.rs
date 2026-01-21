// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::memory_type;
use x86_64::PhysAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

impl MemoryMapEntry {
    pub const fn is_available(&self) -> bool {
        self.entry_type == memory_type::AVAILABLE
    }

    pub const fn is_acpi_reclaimable(&self) -> bool {
        self.entry_type == memory_type::ACPI_RECLAIMABLE
    }

    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr.saturating_add(self.length))
    }

    pub const fn type_name(&self) -> &'static str {
        memory_type::name(self.entry_type)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

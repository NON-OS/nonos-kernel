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

pub mod memory_type {
    pub const AVAILABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

impl MemoryMapEntry {
    #[inline]
    pub fn is_available(&self) -> bool {
        self.entry_type == memory_type::AVAILABLE
    }

    #[inline]
    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    #[inline]
    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr.saturating_add(self.length))
    }

    #[inline]
    pub fn size(&self) -> u64 {
        self.length
    }

    #[inline]
    pub fn page_count(&self) -> u64 {
        self.length / 4096
    }
}

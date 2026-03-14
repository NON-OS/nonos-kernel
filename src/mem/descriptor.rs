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

use super::types::MemoryType;
use super::PhysAddr;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub mem_type: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub num_pages: u64,
    pub attribute: u64,
}

impl MemoryDescriptor {
    pub fn memory_type(&self) -> MemoryType {
        MemoryType::from_u32_or_reserved(self.mem_type)
    }

    pub fn end_address(&self, page_size: u64) -> u64 {
        self.phys_start.saturating_add(self.num_pages.saturating_mul(page_size))
    }

    pub fn size_bytes(&self, page_size: u64) -> u64 {
        self.num_pages.saturating_mul(page_size)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub usable: bool,
}

impl MemoryRegion {
    pub fn new(start: PhysAddr, end: PhysAddr, usable: bool) -> Self {
        Self { start, end, usable }
    }

    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

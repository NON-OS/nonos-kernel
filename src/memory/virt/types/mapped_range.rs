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

use super::flags::VmFlags;
use super::page_size::PageSize;
use x86_64::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy)]
pub struct MappedRange {
    pub start_va: VirtAddr,
    pub start_pa: PhysAddr,
    pub size: usize,
    pub flags: VmFlags,
    pub page_size: PageSize,
}

impl MappedRange {
    pub const fn new(
        start_va: VirtAddr,
        start_pa: PhysAddr,
        size: usize,
        flags: VmFlags,
        page_size: PageSize,
    ) -> Self {
        Self { start_va, start_pa, size, flags, page_size }
    }

    pub fn end_va(&self) -> VirtAddr {
        VirtAddr::new(self.start_va.as_u64() + self.size as u64)
    }

    pub fn contains(&self, va: VirtAddr) -> bool {
        let start = self.start_va.as_u64();
        let end = start + self.size as u64;
        let addr = va.as_u64();
        addr >= start && addr < end
    }

    pub fn translate(&self, va: VirtAddr) -> Option<PhysAddr> {
        if !self.contains(va) {
            return None;
        }
        let offset = va.as_u64() - self.start_va.as_u64();
        Some(PhysAddr::new(self.start_pa.as_u64() + offset))
    }
}

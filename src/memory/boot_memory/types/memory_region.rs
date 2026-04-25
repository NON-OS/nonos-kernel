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

use super::super::constants::PAGE_SIZE_U64;
use super::region_type::RegionType;
use x86_64::PhysAddr;

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub region_type: RegionType,
    pub flags: u32,
}

impl MemoryRegion {
    pub const fn new(start: u64, end: u64, region_type: RegionType, flags: u32) -> Self {
        Self { start: PhysAddr::new(start), end: PhysAddr::new(end), region_type, flags }
    }

    #[inline]
    pub const fn size(&self) -> u64 {
        if self.end.as_u64() > self.start.as_u64() {
            self.end.as_u64() - self.start.as_u64()
        } else {
            0
        }
    }

    #[inline]
    pub const fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE_U64
    }
    #[inline]
    pub const fn contains(&self, addr: PhysAddr) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end.as_u64()
    }
    #[inline]
    pub const fn is_available(&self) -> bool {
        self.region_type.is_allocatable()
    }
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.end.as_u64() <= self.start.as_u64()
    }
    #[inline]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }
}

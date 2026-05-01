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

use super::super::constants::PAGE_SIZE;
use super::region_type::RegionType;
use super::security_level::SecurityLevel;
use crate::memory::addr::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub region_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: usize,
    pub region_type: RegionType,
    pub security_level: SecurityLevel,
    pub owner_process: u64,
    pub encrypted: bool,
    pub creation_time: u64,
    pub access_count: u64,
}

impl MemoryRegion {
    pub const fn new(
        region_id: u64,
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        size: usize,
        region_type: RegionType,
        security_level: SecurityLevel,
        owner_process: u64,
        creation_time: u64,
    ) -> Self {
        Self {
            region_id,
            virtual_addr,
            physical_addr,
            size,
            region_type,
            security_level,
            owner_process,
            encrypted: security_level.requires_encryption(),
            creation_time,
            access_count: 0,
        }
    }

    #[inline]
    pub fn end_addr(&self) -> VirtAddr {
        VirtAddr::new(self.virtual_addr.as_u64().saturating_add(self.size as u64))
    }

    #[inline]
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.virtual_addr && addr < self.end_addr()
    }

    #[inline]
    pub const fn page_count(&self) -> usize {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

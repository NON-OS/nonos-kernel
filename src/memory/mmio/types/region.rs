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

use super::flags::MmioFlags;
use crate::memory::addr::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    pub va: VirtAddr,
    pub pa: PhysAddr,
    pub size: usize,
    pub flags: MmioFlags,
    pub region_id: u64,
}

impl MmioRegion {
    pub const fn new(
        va: VirtAddr,
        pa: PhysAddr,
        size: usize,
        flags: MmioFlags,
        region_id: u64,
    ) -> Self {
        Self { va, pa, size, flags, region_id }
    }

    pub fn end_va(&self) -> VirtAddr {
        VirtAddr::new(self.va.as_u64() + self.size as u64)
    }

    pub fn contains(&self, addr: VirtAddr) -> bool {
        let start = self.va.as_u64();
        let end = start + self.size as u64;
        let a = addr.as_u64();
        a >= start && a < end
    }

    pub fn validate_access(&self, offset: usize, access_size: usize) -> bool {
        offset.checked_add(access_size).map(|end| end <= self.size).unwrap_or(false)
    }

    pub fn offset_addr(&self, offset: usize) -> Option<VirtAddr> {
        if offset < self.size {
            Some(VirtAddr::new(self.va.as_u64() + offset as u64))
        } else {
            None
        }
    }
}

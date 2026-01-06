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

use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
// ============================================================================
// MMIO FLAGS
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioFlags {
    pub cacheable: bool,
    pub write_combining: bool,
    pub user_accessible: bool,
    pub executable: bool,
}

impl MmioFlags {
    pub const fn device() -> Self {
        Self {
            cacheable: false,
            write_combining: false,
            user_accessible: false,
            executable: false,
        }
    }

    pub const fn framebuffer() -> Self {
        Self {
            cacheable: false,
            write_combining: true,
            user_accessible: false,
            executable: false,
        }
    }

    pub const fn user_device() -> Self {
        Self {
            cacheable: false,
            write_combining: false,
            user_accessible: true,
            executable: false,
        }
    }

    pub fn to_vm_flags(self) -> u32 {
        let mut flags = VM_FLAG_PRESENT | VM_FLAG_WRITABLE;

        if !self.executable {
            flags |= VM_FLAG_NX;
        }
        if self.user_accessible {
            flags |= VM_FLAG_USER;
        }
        if !self.cacheable {
            flags |= VM_FLAG_CACHE_DISABLE;
        }
        if self.write_combining {
            flags |= VM_FLAG_WRITE_COMBINE;
        }

        flags
    }
}

impl Default for MmioFlags {
    fn default() -> Self {
        Self::device()
    }
}
// ============================================================================
// MMIO REGION
// ============================================================================
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
        Self {
            va,
            pa,
            size,
            flags,
            region_id,
        }
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
        offset.checked_add(access_size)
            .map(|end| end <= self.size)
            .unwrap_or(false)
    }

    pub fn offset_addr(&self, offset: usize) -> Option<VirtAddr> {
        if offset < self.size {
            Some(VirtAddr::new(self.va.as_u64() + offset as u64))
        } else {
            None
        }
    }
}

// ============================================================================
// STATISTICS SNAPSHOT
// ============================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct MmioStatsSnapshot {
    pub total_regions: usize,
    pub total_mapped_size: u64,
    pub read_operations: u64,
    pub write_operations: u64,
}

impl MmioStatsSnapshot {
    pub const fn new() -> Self {
        Self {
            total_regions: 0,
            total_mapped_size: 0,
            read_operations: 0,
            write_operations: 0,
        }
    }

    pub const fn total_operations(&self) -> u64 {
        self.read_operations + self.write_operations
    }
}

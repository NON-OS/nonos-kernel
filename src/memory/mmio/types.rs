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

//! MMIO Types

use x86_64::{PhysAddr, VirtAddr};

use super::constants::*;

// ============================================================================
// MMIO FLAGS
// ============================================================================

/// Flags for MMIO region mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioFlags {
    /// Region is cacheable
    pub cacheable: bool,
    /// Region uses write-combining
    pub write_combining: bool,
    /// Region is accessible from user space
    pub user_accessible: bool,
    /// Region is executable
    pub executable: bool,
}

impl MmioFlags {
    /// Creates flags for a standard device register region.
    pub const fn device() -> Self {
        Self {
            cacheable: false,
            write_combining: false,
            user_accessible: false,
            executable: false,
        }
    }

    /// Creates flags for a framebuffer region.
    pub const fn framebuffer() -> Self {
        Self {
            cacheable: false,
            write_combining: true,
            user_accessible: false,
            executable: false,
        }
    }

    /// Creates flags for a user-accessible device region.
    pub const fn user_device() -> Self {
        Self {
            cacheable: false,
            write_combining: false,
            user_accessible: true,
            executable: false,
        }
    }

    /// Converts to internal VM flags representation.
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

/// Represents a mapped MMIO region.
#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    /// Virtual address of the region
    pub va: VirtAddr,
    /// Physical address of the region
    pub pa: PhysAddr,
    /// Size of the region in bytes
    pub size: usize,
    /// Mapping flags
    pub flags: MmioFlags,
    /// Unique region identifier
    pub region_id: u64,
}

impl MmioRegion {
    /// Creates a new MMIO region.
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

    /// Returns the end virtual address.
    pub fn end_va(&self) -> VirtAddr {
        VirtAddr::new(self.va.as_u64() + self.size as u64)
    }

    /// Checks if a virtual address is within this region.
    pub fn contains(&self, addr: VirtAddr) -> bool {
        let start = self.va.as_u64();
        let end = start + self.size as u64;
        let a = addr.as_u64();
        a >= start && a < end
    }

    /// Validates an access is within bounds.
    pub fn validate_access(&self, offset: usize, access_size: usize) -> bool {
        offset.checked_add(access_size)
            .map(|end| end <= self.size)
            .unwrap_or(false)
    }

    /// Returns the virtual address for an offset.
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

/// Snapshot of MMIO statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmioStatsSnapshot {
    /// Total mapped regions
    pub total_regions: usize,
    /// Total mapped size in bytes
    pub total_mapped_size: u64,
    /// Total read operations
    pub read_operations: u64,
    /// Total write operations
    pub write_operations: u64,
}

impl MmioStatsSnapshot {
    /// Creates an empty stats snapshot.
    pub const fn new() -> Self {
        Self {
            total_regions: 0,
            total_mapped_size: 0,
            read_operations: 0,
            write_operations: 0,
        }
    }

    /// Returns total I/O operations.
    pub const fn total_operations(&self) -> u64 {
        self.read_operations + self.write_operations
    }
}

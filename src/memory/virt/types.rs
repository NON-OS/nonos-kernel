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

//! Virtual Memory Manager Types

use x86_64::{PhysAddr, VirtAddr};

use super::constants::*;

// ============================================================================
// VM FLAGS
// ============================================================================

/// Virtual memory mapping flags.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFlags {
    /// No flags
    None = 0,
    /// Page is present
    Present = PTE_PRESENT,
    /// Page is writable
    Write = PTE_WRITABLE,
    /// Page is user-accessible
    User = PTE_USER,
    /// Write-through caching
    WriteThrough = PTE_WRITE_THROUGH,
    /// Cache disabled
    CacheDisable = PTE_CACHE_DISABLE,
    /// Global (not flushed on CR3 switch)
    Global = PTE_GLOBAL,
    /// No execute
    NoExecute = PTE_NO_EXECUTE,
}

impl VmFlags {
    /// Alias for readable mapping
    pub const READ: VmFlags = VmFlags::Present;
    /// Alias for read-write (backwards compat)
    pub const RW: VmFlags = VmFlags::Write;
    /// Alias for read-write
    pub const READ_WRITE: VmFlags = VmFlags::Present;
    /// Alias for no-execute
    pub const NX: VmFlags = VmFlags::NoExecute;
    /// Alias for write-through
    pub const PWT: VmFlags = VmFlags::WriteThrough;
    /// Alias for cache-disable
    pub const PCD: VmFlags = VmFlags::CacheDisable;
    /// Alias for global
    pub const GLOBAL: VmFlags = VmFlags::Global;
    /// Alias for user
    pub const USER: VmFlags = VmFlags::User;

    /// Checks if this flag set contains another flag.
    #[inline]
    pub const fn contains(self, other: VmFlags) -> bool {
        (self as u64) & (other as u64) != 0
    }

    /// Returns the raw bits.
    #[inline]
    pub const fn bits(self) -> u64 {
        self as u64
    }
}

impl core::ops::BitOr for VmFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        // SAFETY: All bit combinations are valid for VmFlags
        unsafe { core::mem::transmute((self as u64) | (rhs as u64)) }
    }
}

impl core::ops::BitOrAssign for VmFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl core::ops::BitAnd for VmFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        // SAFETY: All bit combinations are valid for VmFlags
        unsafe { core::mem::transmute((self as u64) & (rhs as u64)) }
    }
}

impl Default for VmFlags {
    fn default() -> Self {
        Self::None
    }
}

// ============================================================================
// PAGE SIZE
// ============================================================================

/// Supported page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum PageSize {
    /// 4 KiB page
    Size4K = PAGE_SIZE_4K,
    /// 2 MiB huge page
    Size2M = PAGE_SIZE_2M,
    /// 1 GiB giant page
    Size1G = PAGE_SIZE_1G,
}

impl PageSize {
    /// Returns the size in bytes.
    #[inline]
    pub const fn bytes(self) -> usize {
        self as usize
    }

    /// Returns the alignment mask.
    #[inline]
    pub const fn mask(self) -> u64 {
        (self as u64) - 1
    }

    /// Checks if an address is aligned to this page size.
    #[inline]
    pub const fn is_aligned(self, addr: u64) -> bool {
        addr & self.mask() == 0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::Size4K
    }
}

// ============================================================================
// MAPPED RANGE
// ============================================================================

/// Represents a mapped virtual memory range.
#[derive(Debug, Clone, Copy)]
pub struct MappedRange {
    /// Start virtual address
    pub start_va: VirtAddr,
    /// Start physical address
    pub start_pa: PhysAddr,
    /// Size in bytes
    pub size: usize,
    /// Mapping flags
    pub flags: VmFlags,
    /// Page size used
    pub page_size: PageSize,
}

impl MappedRange {
    /// Creates a new mapped range.
    pub const fn new(
        start_va: VirtAddr,
        start_pa: PhysAddr,
        size: usize,
        flags: VmFlags,
        page_size: PageSize,
    ) -> Self {
        Self {
            start_va,
            start_pa,
            size,
            flags,
            page_size,
        }
    }

    /// Returns the end virtual address.
    pub fn end_va(&self) -> VirtAddr {
        VirtAddr::new(self.start_va.as_u64() + self.size as u64)
    }

    /// Checks if a virtual address is within this range.
    pub fn contains(&self, va: VirtAddr) -> bool {
        let start = self.start_va.as_u64();
        let end = start + self.size as u64;
        let addr = va.as_u64();
        addr >= start && addr < end
    }

    /// Translates a virtual address to physical within this range.
    pub fn translate(&self, va: VirtAddr) -> Option<PhysAddr> {
        if !self.contains(va) {
            return None;
        }
        let offset = va.as_u64() - self.start_va.as_u64();
        Some(PhysAddr::new(self.start_pa.as_u64() + offset))
    }
}

// ============================================================================
// STATISTICS SNAPSHOT
// ============================================================================

/// Snapshot of virtual memory statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmStatsSnapshot {
    /// Total mapped pages
    pub mapped_pages: usize,
    /// Total mapped memory in bytes
    pub mapped_memory: u64,
    /// Total page faults handled
    pub page_faults: u64,
    /// Total TLB flushes
    pub tlb_flushes: u64,
    /// W^X violations detected
    pub wx_violations: u64,
}

impl VmStatsSnapshot {
    /// Creates an empty stats snapshot.
    pub const fn new() -> Self {
        Self {
            mapped_pages: 0,
            mapped_memory: 0,
            page_faults: 0,
            tlb_flushes: 0,
            wx_violations: 0,
        }
    }
}

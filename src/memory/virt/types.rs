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
// VM FLAGS
// ============================================================================
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFlags {
    None = 0,
    Present = PTE_PRESENT,
    Write = PTE_WRITABLE,
    User = PTE_USER,
    WriteThrough = PTE_WRITE_THROUGH,
    CacheDisable = PTE_CACHE_DISABLE,
    Global = PTE_GLOBAL,
    NoExecute = PTE_NO_EXECUTE,
}

impl VmFlags {
    pub const READ: VmFlags = VmFlags::Present;
    pub const RW: VmFlags = VmFlags::Write;
    pub const READ_WRITE: VmFlags = VmFlags::Present;
    pub const NX: VmFlags = VmFlags::NoExecute;
    pub const PWT: VmFlags = VmFlags::WriteThrough;
    pub const PCD: VmFlags = VmFlags::CacheDisable;
    pub const GLOBAL: VmFlags = VmFlags::Global;
    pub const USER: VmFlags = VmFlags::User;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum PageSize {
    Size4K = PAGE_SIZE_4K,
    Size2M = PAGE_SIZE_2M,
    Size1G = PAGE_SIZE_1G,
}

impl PageSize {
    #[inline]
    pub const fn bytes(self) -> usize {
        self as usize
    }

    #[inline]
    pub const fn mask(self) -> u64 {
        (self as u64) - 1
    }

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
        Self {
            start_va,
            start_pa,
            size,
            flags,
            page_size,
        }
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

// ============================================================================
// STATISTICS SNAPSHOT
// ============================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct VmStatsSnapshot {
    pub mapped_pages: usize,
    pub mapped_memory: u64,
    pub page_faults: u64,
    pub tlb_flushes: u64,
    pub wx_violations: u64,
}

impl VmStatsSnapshot {
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

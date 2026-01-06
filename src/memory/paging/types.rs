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

extern crate alloc;
use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
// ============================================================================
// PAGE PERMISSIONS
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PagePermissions {
    bits: u32,
}

impl PagePermissions {
    pub const READ: Self = Self { bits: PERM_READ };
    pub const WRITE: Self = Self { bits: PERM_WRITE };
    pub const EXECUTE: Self = Self { bits: PERM_EXECUTE };
    pub const USER: Self = Self { bits: PERM_USER };
    pub const GLOBAL: Self = Self { bits: PERM_GLOBAL };
    pub const NO_CACHE: Self = Self { bits: PERM_NO_CACHE };
    pub const WRITE_THROUGH: Self = Self {
        bits: PERM_WRITE_THROUGH,
    };

    pub const COW: Self = Self { bits: PERM_COW };
    pub const DEMAND: Self = Self { bits: PERM_DEMAND };
    pub const ZERO_FILL: Self = Self { bits: PERM_ZERO_FILL };
    pub const SHARED: Self = Self { bits: PERM_SHARED };
    pub const LOCKED: Self = Self { bits: PERM_LOCKED };
    pub const DEVICE: Self = Self { bits: PERM_DEVICE };
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    pub const fn bits(&self) -> u32 {
        self.bits
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    pub const fn remove(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }

    pub const fn insert(self, other: Self) -> Self {
        self.union(other)
    }

    pub const fn is_wx_violation(&self) -> bool {
        self.contains(Self::WRITE) && self.contains(Self::EXECUTE)
    }

    pub const fn to_pte_flags(&self) -> u64 {
        let mut flags = PTE_PRESENT;
      
        if self.contains(Self::WRITE) {
            flags |= PTE_WRITABLE;
        }
        if self.contains(Self::USER) {
            flags |= PTE_USER;
        }
        if self.contains(Self::WRITE_THROUGH) {
            flags |= PTE_WRITE_THROUGH;
        }
        if self.contains(Self::NO_CACHE) {
            flags |= PTE_CACHE_DISABLE;
        }
        if self.contains(Self::GLOBAL) {
            flags |= PTE_GLOBAL;
        }
        if !self.contains(Self::EXECUTE) {
            flags |= PTE_NO_EXECUTE;
        }

        flags
    }

    pub const fn kernel_ro() -> Self {
        Self { bits: PERM_READ }
    }

    pub const fn kernel_rw() -> Self {
        Self {
            bits: PERM_READ | PERM_WRITE,
        }
    }

    pub const fn kernel_rx() -> Self {
        Self {
            bits: PERM_READ | PERM_EXECUTE,
        }
    }

    pub const fn user_ro() -> Self {
        Self {
            bits: PERM_READ | PERM_USER,
        }
    }

    pub const fn user_rw() -> Self {
        Self {
            bits: PERM_READ | PERM_WRITE | PERM_USER,
        }
    }

    pub const fn user_rx() -> Self {
        Self {
            bits: PERM_READ | PERM_EXECUTE | PERM_USER,
        }
    }

    pub const fn device() -> Self {
        Self {
            bits: PERM_READ | PERM_WRITE | PERM_NO_CACHE | PERM_DEVICE,
        }
    }
}

impl core::ops::BitOr for PagePermissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for PagePermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

impl core::ops::BitAnd for PagePermissions {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self {
            bits: self.bits & rhs.bits,
        }
    }
}
// ============================================================================
// PAGE SIZE
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Size4KiB,
    Size2MiB,
    Size1GiB,
}

impl PageSize {
    pub const fn bytes(&self) -> usize {
        match self {
            Self::Size4KiB => PAGE_SIZE_4K,
            Self::Size2MiB => PAGE_SIZE_2M,
            Self::Size1GiB => PAGE_SIZE_1G,
        }
    }

    pub const fn align_mask(&self) -> u64 {
        match self {
            Self::Size4KiB => 0xFFF,
            Self::Size2MiB => 0x1F_FFFF,
            Self::Size1GiB => 0x3FFF_FFFF,
        }
    }

    pub const fn is_aligned(&self, addr: u64) -> bool {
        addr & self.align_mask() == 0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::Size4KiB
    }
}

// ============================================================================
// PAGE MAPPING
// ============================================================================
#[derive(Debug, Clone)]
pub struct PageMapping {
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub size: PageSize,
    pub permissions: PagePermissions,
    pub process_id: Option<u32>,
    pub reference_count: u32,
    pub creation_time: u64,
    pub last_accessed: u64,
}

impl PageMapping {
    pub fn new(
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        size: PageSize,
        permissions: PagePermissions,
    ) -> Self {
        Self {
            virtual_addr,
            physical_addr,
            size,
            permissions,
            process_id: None,
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        }
    }

    pub fn kernel(virtual_addr: VirtAddr, physical_addr: PhysAddr, permissions: PagePermissions) -> Self {
        Self {
            virtual_addr,
            physical_addr,
            size: PageSize::Size4KiB,
            permissions,
            process_id: None,
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        }
    }

    pub fn user(
        virtual_addr: VirtAddr,
        physical_addr: PhysAddr,
        permissions: PagePermissions,
        process_id: u32,
    ) -> Self {
        Self {
            virtual_addr,
            physical_addr,
            size: PageSize::Size4KiB,
            permissions,
            process_id: Some(process_id),
            reference_count: 1,
            creation_time: get_timestamp(),
            last_accessed: get_timestamp(),
        }
    }

    pub const fn is_kernel(&self) -> bool {
        self.process_id.is_none()
    }

    pub const fn is_user(&self) -> bool {
        self.process_id.is_some()
    }

    pub const fn is_huge(&self) -> bool {
        matches!(self.size, PageSize::Size2MiB | PageSize::Size1GiB)
    }

    pub const fn is_shared(&self) -> bool {
        self.reference_count > 1 || self.permissions.contains(PagePermissions::SHARED)
    }

    pub fn touch(&mut self) {
        self.last_accessed = get_timestamp();
    }
}
// ============================================================================
// ADDRESS SPACE
// ============================================================================
#[derive(Debug, Clone)]
pub struct AddressSpace {
    pub asid: u32,
    pub cr3_value: PhysAddr,
    pub mappings: Vec<VirtAddr>,
    pub process_id: u32,
    pub creation_time: u64,
}

impl AddressSpace {
    pub fn new(asid: u32, cr3_value: PhysAddr, process_id: u32) -> Self {
        Self {
            asid,
            cr3_value,
            mappings: Vec::new(),
            process_id,
            creation_time: get_timestamp(),
        }
    }

    pub const fn is_kernel(&self) -> bool {
        self.asid == KERNEL_ASID
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    pub fn add_mapping(&mut self, va: VirtAddr) {
        self.mappings.push(va);
    }

  pub fn remove_mapping(&mut self, va: VirtAddr) {
        self.mappings.retain(|&addr| addr != va);
    }
}
// ============================================================================
// PAGING STATS (PUBLIC SNAPSHOT)
// ============================================================================
#[derive(Debug, Clone, Default)]
pub struct PagingStats {
    pub total_mappings: usize,
    pub address_spaces: usize,
    pub page_faults: u64,
    pub tlb_flushes: u64,
    pub cow_faults: u64,
    pub demand_loads: u64,
    pub huge_pages: usize,
    pub user_pages: usize,
    pub kernel_pages: usize,
    pub page_modifications: u64,
}
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
#[inline]
pub fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe to call
    unsafe { core::arch::x86_64::_rdtsc() }
}

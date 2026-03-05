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

//! Paging Types

extern crate alloc;

use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr};

use super::constants::*;

// ============================================================================
// PAGE PERMISSIONS
// ============================================================================

/// Page permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PagePermissions {
    bits: u32,
}

impl PagePermissions {
    /// Read permission
    pub const READ: Self = Self { bits: PERM_READ };

    /// Write permission
    pub const WRITE: Self = Self { bits: PERM_WRITE };

    /// Execute permission
    pub const EXECUTE: Self = Self { bits: PERM_EXECUTE };

    /// User accessible
    pub const USER: Self = Self { bits: PERM_USER };

    /// Global page (not flushed on CR3 switch)
    pub const GLOBAL: Self = Self { bits: PERM_GLOBAL };

    /// No cache
    pub const NO_CACHE: Self = Self { bits: PERM_NO_CACHE };

    /// Write-through caching
    pub const WRITE_THROUGH: Self = Self {
        bits: PERM_WRITE_THROUGH,
    };

    /// Copy-on-write
    pub const COW: Self = Self { bits: PERM_COW };

    /// Demand paging
    pub const DEMAND: Self = Self { bits: PERM_DEMAND };

    /// Zero-fill on demand
    pub const ZERO_FILL: Self = Self { bits: PERM_ZERO_FILL };

    /// Shared mapping
    pub const SHARED: Self = Self { bits: PERM_SHARED };

    /// Locked (cannot be swapped)
    pub const LOCKED: Self = Self { bits: PERM_LOCKED };

    /// Device memory
    pub const DEVICE: Self = Self { bits: PERM_DEVICE };

    /// Creates empty permissions.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates permissions from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns the raw bits.
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Checks if this contains all bits of other.
    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Returns union of two permissions.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns permissions with other removed.
    pub const fn remove(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }

    /// Returns union (alias for union).
    pub const fn insert(self, other: Self) -> Self {
        self.union(other)
    }

    /// Checks if this is a W^X violation (writable AND executable).
    pub const fn is_wx_violation(&self) -> bool {
        self.contains(Self::WRITE) && self.contains(Self::EXECUTE)
    }

    /// Converts to x86-64 page table entry flags.
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

    /// Creates kernel read-only permissions.
    pub const fn kernel_ro() -> Self {
        Self { bits: PERM_READ }
    }

    /// Creates kernel read-write permissions.
    pub const fn kernel_rw() -> Self {
        Self {
            bits: PERM_READ | PERM_WRITE,
        }
    }

    /// Creates kernel execute permissions.
    pub const fn kernel_rx() -> Self {
        Self {
            bits: PERM_READ | PERM_EXECUTE,
        }
    }

    /// Creates user read-only permissions.
    pub const fn user_ro() -> Self {
        Self {
            bits: PERM_READ | PERM_USER,
        }
    }

    /// Creates user read-write permissions.
    pub const fn user_rw() -> Self {
        Self {
            bits: PERM_READ | PERM_WRITE | PERM_USER,
        }
    }

    /// Creates user execute permissions.
    pub const fn user_rx() -> Self {
        Self {
            bits: PERM_READ | PERM_EXECUTE | PERM_USER,
        }
    }

    /// Creates device memory permissions.
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

/// Page size variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KiB standard page
    Size4KiB,
    /// 2 MiB huge page
    Size2MiB,
    /// 1 GiB gigantic page
    Size1GiB,
}

impl PageSize {
    /// Returns the size in bytes.
    pub const fn bytes(&self) -> usize {
        match self {
            Self::Size4KiB => PAGE_SIZE_4K,
            Self::Size2MiB => PAGE_SIZE_2M,
            Self::Size1GiB => PAGE_SIZE_1G,
        }
    }

    /// Returns the alignment mask for this page size.
    pub const fn align_mask(&self) -> u64 {
        match self {
            Self::Size4KiB => 0xFFF,
            Self::Size2MiB => 0x1F_FFFF,
            Self::Size1GiB => 0x3FFF_FFFF,
        }
    }

    /// Returns true if address is aligned to this page size.
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

/// Represents a single page mapping.
#[derive(Debug, Clone)]
pub struct PageMapping {
    /// Virtual address of the page
    pub virtual_addr: VirtAddr,
    /// Physical address of the page
    pub physical_addr: PhysAddr,
    /// Page size
    pub size: PageSize,
    /// Permissions
    pub permissions: PagePermissions,
    /// Owning process ID (None for kernel pages)
    pub process_id: Option<u32>,
    /// Reference count for shared pages
    pub reference_count: u32,
    /// Timestamp when mapping was created
    pub creation_time: u64,
    /// Timestamp of last access
    pub last_accessed: u64,
}

impl PageMapping {
    /// Creates a new page mapping.
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

    /// Creates a kernel page mapping.
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

    /// Creates a user page mapping.
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

    /// Returns true if this is a kernel mapping.
    pub const fn is_kernel(&self) -> bool {
        self.process_id.is_none()
    }

    /// Returns true if this is a user mapping.
    pub const fn is_user(&self) -> bool {
        self.process_id.is_some()
    }

    /// Returns true if this is a huge page.
    pub const fn is_huge(&self) -> bool {
        matches!(self.size, PageSize::Size2MiB | PageSize::Size1GiB)
    }

    /// Returns true if this mapping is shared.
    pub const fn is_shared(&self) -> bool {
        self.reference_count > 1 || self.permissions.contains(PagePermissions::SHARED)
    }

    /// Updates the last accessed timestamp.
    pub fn touch(&mut self) {
        self.last_accessed = get_timestamp();
    }
}

// ============================================================================
// ADDRESS SPACE
// ============================================================================

/// Represents a process address space.
#[derive(Debug, Clone)]
pub struct AddressSpace {
    /// Address space identifier
    pub asid: u32,
    /// CR3 value (physical address of PML4)
    pub cr3_value: PhysAddr,
    /// Virtual addresses of all mappings
    pub mappings: Vec<VirtAddr>,
    /// Owning process ID
    pub process_id: u32,
    /// Timestamp when created
    pub creation_time: u64,
}

impl AddressSpace {
    /// Creates a new address space.
    pub fn new(asid: u32, cr3_value: PhysAddr, process_id: u32) -> Self {
        Self {
            asid,
            cr3_value,
            mappings: Vec::new(),
            process_id,
            creation_time: get_timestamp(),
        }
    }

    /// Returns true if this is the kernel address space.
    pub const fn is_kernel(&self) -> bool {
        self.asid == KERNEL_ASID
    }

    /// Returns the number of mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Adds a mapping to this address space.
    pub fn add_mapping(&mut self, va: VirtAddr) {
        self.mappings.push(va);
    }

    /// Removes a mapping from this address space.
    pub fn remove_mapping(&mut self, va: VirtAddr) {
        self.mappings.retain(|&addr| addr != va);
    }
}

// ============================================================================
// PAGING STATS (PUBLIC SNAPSHOT)
// ============================================================================

/// Snapshot of paging statistics.
#[derive(Debug, Clone, Default)]
pub struct PagingStats {
    /// Total number of page mappings
    pub total_mappings: usize,
    /// Number of address spaces
    pub address_spaces: usize,
    /// Total page faults handled
    pub page_faults: u64,
    /// Total TLB flushes
    pub tlb_flushes: u64,
    /// Copy-on-write faults handled
    pub cow_faults: u64,
    /// Demand loads handled
    pub demand_loads: u64,
    /// Number of huge pages mapped
    pub huge_pages: usize,
    /// Number of user pages
    pub user_pages: usize,
    /// Number of kernel pages
    pub kernel_pages: usize,
    /// Number of page protection changes
    pub page_modifications: u64,
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Gets current timestamp (TSC).
#[inline]
pub fn get_timestamp() -> u64 {
    // SAFETY: rdtsc is always safe to call
    unsafe { core::arch::x86_64::_rdtsc() }
}

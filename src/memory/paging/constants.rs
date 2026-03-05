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

//! Paging Constants
//!
//! All named constants for the paging subsystem.

// ============================================================================
// PAGE TABLE ENTRY FLAGS
// ============================================================================

/// Present bit (bit 0)
pub const PTE_PRESENT: u64 = 1 << 0;

/// Writable bit (bit 1)
pub const PTE_WRITABLE: u64 = 1 << 1;

/// User accessible bit (bit 2)
pub const PTE_USER: u64 = 1 << 2;

/// Write-through caching bit (bit 3)
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;

/// Cache disable bit (bit 4)
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// Accessed bit (bit 5)
pub const PTE_ACCESSED: u64 = 1 << 5;

/// Dirty bit (bit 6)
pub const PTE_DIRTY: u64 = 1 << 6;

/// Huge page bit (bit 7) - 2MiB in PD, 1GiB in PDPT
pub const PTE_HUGE_PAGE: u64 = 1 << 7;

/// Global bit (bit 8)
pub const PTE_GLOBAL: u64 = 1 << 8;

/// No-execute bit (bit 63)
pub const PTE_NO_EXECUTE: u64 = 1u64 << 63;

/// Mask for physical address in PTE (bits 12-51)
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Mask for flags in PTE (bits 0-11 and 63)
pub const PTE_FLAGS_MASK: u64 = 0xFFF0_0000_0000_0FFF;

// ============================================================================
// PAGE TABLE ENTRY FLAG SHORTCUTS
// ============================================================================

/// Present + Writable + User (for intermediate tables)
pub const PTE_TABLE_FLAGS: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_USER;

/// Kernel page flags (Present only, intermediate entries)
pub const PTE_KERNEL_TABLE: u64 = PTE_PRESENT | PTE_WRITABLE;

// ============================================================================
// PAGE TABLE INDICES
// ============================================================================

/// Number of entries per page table
pub const PAGE_TABLE_ENTRIES: usize = 512;

/// Bits to shift for PML4 index
pub const PML4_SHIFT: u64 = 39;

/// Bits to shift for PDPT index
pub const PDPT_SHIFT: u64 = 30;

/// Bits to shift for PD index
pub const PD_SHIFT: u64 = 21;

/// Bits to shift for PT index
pub const PT_SHIFT: u64 = 12;

/// Index mask (9 bits)
pub const INDEX_MASK: u64 = 0x1FF;

/// Page offset mask (12 bits)
pub const PAGE_OFFSET_MASK: u64 = 0xFFF;

// ============================================================================
// PAGE SIZES
// ============================================================================

/// 4 KiB page size
pub const PAGE_SIZE_4K: usize = 4096;

/// 2 MiB huge page size
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;

/// 1 GiB huge page size
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

// ============================================================================
// PAGE FAULT ERROR CODES
// ============================================================================

/// Page fault caused by non-present page
pub const PF_PRESENT: u64 = 1 << 0;

/// Page fault caused by write access
pub const PF_WRITE: u64 = 1 << 1;

/// Page fault in user mode
pub const PF_USER: u64 = 1 << 2;

/// Page fault caused by reserved bit violation
pub const PF_RESERVED: u64 = 1 << 3;

/// Page fault caused by instruction fetch
pub const PF_INSTRUCTION: u64 = 1 << 4;

/// Page fault caused by protection key
pub const PF_PROTECTION_KEY: u64 = 1 << 5;

/// Page fault caused by shadow stack
pub const PF_SHADOW_STACK: u64 = 1 << 6;

// ============================================================================
// CR0 BITS
// ============================================================================

/// Write Protect bit in CR0 (bit 16)
pub const CR0_WP: u64 = 1 << 16;

/// CR0 mask for enabling write protection
pub const CR0_WP_ENABLE_MASK: u32 = 0x10000;

/// CR0 mask for disabling write protection
pub const CR0_WP_DISABLE_MASK: u32 = 0xFFFE_FFFF;

// ============================================================================
// PERMISSION BITS (for PagePermissions)
// ============================================================================

/// Read permission
pub const PERM_READ: u32 = 1 << 0;

/// Write permission
pub const PERM_WRITE: u32 = 1 << 1;

/// Execute permission
pub const PERM_EXECUTE: u32 = 1 << 2;

/// User accessible
pub const PERM_USER: u32 = 1 << 3;

/// Global page (not flushed on CR3 switch)
pub const PERM_GLOBAL: u32 = 1 << 4;

/// No cache
pub const PERM_NO_CACHE: u32 = 1 << 5;

/// Write-through
pub const PERM_WRITE_THROUGH: u32 = 1 << 6;

/// Copy-on-write
pub const PERM_COW: u32 = 1 << 7;

/// Demand paging
pub const PERM_DEMAND: u32 = 1 << 8;

/// Zero-fill on demand
pub const PERM_ZERO_FILL: u32 = 1 << 9;

/// Shared mapping
pub const PERM_SHARED: u32 = 1 << 10;

/// Locked (cannot be swapped)
pub const PERM_LOCKED: u32 = 1 << 11;

/// Device memory
pub const PERM_DEVICE: u32 = 1 << 12;

// ============================================================================
// ADDRESS SPACE CONSTANTS
// ============================================================================

/// Kernel address space ASID
pub const KERNEL_ASID: u32 = 0;

/// First user ASID
pub const FIRST_USER_ASID: u32 = 1;

/// Kernel space starts at PML4 index 256
pub const KERNEL_PML4_START: usize = 256;

/// Number of kernel PML4 entries (256-511)
pub const KERNEL_PML4_COUNT: usize = 256;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Extracts PML4 index from virtual address.
#[inline]
pub const fn pml4_index(va: u64) -> usize {
    ((va >> PML4_SHIFT) & INDEX_MASK) as usize
}

/// Extracts PDPT index from virtual address.
#[inline]
pub const fn pdpt_index(va: u64) -> usize {
    ((va >> PDPT_SHIFT) & INDEX_MASK) as usize
}

/// Extracts PD index from virtual address.
#[inline]
pub const fn pd_index(va: u64) -> usize {
    ((va >> PD_SHIFT) & INDEX_MASK) as usize
}

/// Extracts PT index from virtual address.
#[inline]
pub const fn pt_index(va: u64) -> usize {
    ((va >> PT_SHIFT) & INDEX_MASK) as usize
}

/// Extracts page offset from virtual address.
#[inline]
pub const fn page_offset(va: u64) -> usize {
    (va & PAGE_OFFSET_MASK) as usize
}

/// Checks if a PTE is present.
#[inline]
pub const fn pte_is_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

/// Checks if a PTE is a huge page.
#[inline]
pub const fn pte_is_huge(pte: u64) -> bool {
    pte & PTE_HUGE_PAGE != 0
}

/// Extracts physical address from PTE.
#[inline]
pub const fn pte_address(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}

/// Aligns address down to page boundary.
#[inline]
pub const fn page_align_down(addr: u64) -> u64 {
    addr & !PAGE_OFFSET_MASK
}

/// Aligns address up to page boundary.
#[inline]
pub const fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_OFFSET_MASK) & !PAGE_OFFSET_MASK
}

/// Calculates number of pages needed for size.
#[inline]
pub const fn pages_needed(size: usize) -> usize {
    (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K
}

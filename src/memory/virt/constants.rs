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

//! Virtual Memory Manager Constants
//!
//! Defines page sizes, table structure, and PTE flag constants.

// ============================================================================
// PAGE SIZES
// ============================================================================

/// Standard 4 KiB page size
pub const PAGE_SIZE_4K: usize = 4096;

/// 2 MiB huge page size
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;

/// 1 GiB giant page size
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

/// Default page size
pub const PAGE_SIZE: usize = PAGE_SIZE_4K;

// ============================================================================
// PAGE TABLE CONSTANTS
// ============================================================================

/// Entries per page table
pub const PAGE_TABLE_ENTRIES: usize = 512;

/// Page table entry size in bytes
pub const PTE_SIZE: usize = 8;

/// Mask for page table index (9 bits)
pub const PAGE_TABLE_INDEX_MASK: u64 = 0x1FF;

/// Shift for L4 (PML4) table index
pub const L4_INDEX_SHIFT: u64 = 39;

/// Shift for L3 (PDPT) table index
pub const L3_INDEX_SHIFT: u64 = 30;

/// Shift for L2 (PD) table index
pub const L2_INDEX_SHIFT: u64 = 21;

/// Shift for L1 (PT) table index
pub const L1_INDEX_SHIFT: u64 = 12;

// ============================================================================
// PTE FLAG BITS
// ============================================================================

/// Present bit (P)
pub const PTE_PRESENT: u64 = 1 << 0;

/// Read/Write bit (R/W)
pub const PTE_WRITABLE: u64 = 1 << 1;

/// User/Supervisor bit (U/S)
pub const PTE_USER: u64 = 1 << 2;

/// Page-level Write-Through (PWT)
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;

/// Page-level Cache-Disable (PCD)
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// Accessed bit (A)
pub const PTE_ACCESSED: u64 = 1 << 5;

/// Dirty bit (D)
pub const PTE_DIRTY: u64 = 1 << 6;

/// Page Size bit (PS) - for 2M/1G pages
pub const PTE_HUGE_PAGE: u64 = 1 << 7;

/// Global bit (G)
pub const PTE_GLOBAL: u64 = 1 << 8;

/// No Execute bit (NX)
pub const PTE_NO_EXECUTE: u64 = 1u64 << 63;

/// Mask for physical address in PTE
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Mask for PTE flags
pub const PTE_FLAGS_MASK: u64 = !PTE_ADDR_MASK;

// ============================================================================
// CR4 BITS
// ============================================================================

/// PCIDE (Process-Context Identifiers Enable) bit in CR4
pub const CR4_PCIDE: u64 = 1 << 17;

// ============================================================================
// PAGE FAULT ERROR CODE BITS
// ============================================================================

/// Page fault: page was present
pub const PF_PRESENT: u64 = 1 << 0;

/// Page fault: caused by write
pub const PF_WRITE: u64 = 1 << 1;

/// Page fault: from user mode
pub const PF_USER: u64 = 1 << 2;

/// Page fault: reserved bit set
pub const PF_RESERVED: u64 = 1 << 3;

/// Page fault: instruction fetch
pub const PF_INSTRUCTION: u64 = 1 << 4;

/// Page fault: protection key violation
pub const PF_PROTECTION_KEY: u64 = 1 << 5;

/// Page fault: shadow stack access
pub const PF_SHADOW_STACK: u64 = 1 << 6;

// ============================================================================
// INDEX EXTRACTION HELPERS
// ============================================================================

/// Extracts the L4 (PML4) index from a virtual address.
#[inline]
pub const fn l4_index(va: u64) -> usize {
    ((va >> L4_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

/// Extracts the L3 (PDPT) index from a virtual address.
#[inline]
pub const fn l3_index(va: u64) -> usize {
    ((va >> L3_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

/// Extracts the L2 (PD) index from a virtual address.
#[inline]
pub const fn l2_index(va: u64) -> usize {
    ((va >> L2_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

/// Extracts the L1 (PT) index from a virtual address.
#[inline]
pub const fn l1_index(va: u64) -> usize {
    ((va >> L1_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

/// Checks if a PTE is present.
#[inline]
pub const fn pte_is_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

/// Extracts the physical address from a PTE.
#[inline]
pub const fn pte_address(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}

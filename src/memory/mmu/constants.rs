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

//! MMU Constants
//!
//! Page table bits, control register bits, and MSR addresses.

// ============================================================================
// PAGE TABLE ENTRY BITS
// ============================================================================

/// Present bit
pub const PTE_PRESENT: u64 = 1 << 0;

/// Writable bit
pub const PTE_WRITABLE: u64 = 1 << 1;

/// User accessible bit
pub const PTE_USER: u64 = 1 << 2;

/// Write-through bit
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;

/// Cache disabled bit
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// Accessed bit
pub const PTE_ACCESSED: u64 = 1 << 5;

/// Dirty bit
pub const PTE_DIRTY: u64 = 1 << 6;

/// Huge page bit (2MB/1GB)
pub const PTE_HUGE_PAGE: u64 = 1 << 7;

/// Global bit
pub const PTE_GLOBAL: u64 = 1 << 8;

/// No-execute bit
pub const PTE_NO_EXECUTE: u64 = 1u64 << 63;

/// Mask for physical address in PTE
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ============================================================================
// CR4 BITS
// ============================================================================

/// Page Global Enable
pub const CR4_PGE: u64 = 1 << 7;

/// SMEP (Supervisor Mode Execution Prevention)
pub const CR4_SMEP: u64 = 1 << 20;

/// SMAP (Supervisor Mode Access Prevention)
pub const CR4_SMAP: u64 = 1 << 21;

// ============================================================================
// CPUID BITS
// ============================================================================

/// CPUID leaf for extended features
pub const CPUID_FEATURES_LEAF: u32 = 0x07;

/// CPUID EBX bit for SMEP
pub const CPUID_EBX_SMEP: u32 = 1 << 7;

/// CPUID EBX bit for SMAP
pub const CPUID_EBX_SMAP: u32 = 1 << 20;

/// CPUID leaf for extended processor info
pub const CPUID_EXTENDED_LEAF: u32 = 0x8000_0001;

/// CPUID EDX bit for NX support
pub const CPUID_EDX_NX: u32 = 1 << 20;

// ============================================================================
// MSR ADDRESSES
// ============================================================================

/// IA32_EFER MSR address
pub const MSR_IA32_EFER: u32 = 0xC000_0080;

/// IA32_EFER NXE bit (No-Execute Enable)
pub const EFER_NXE: u64 = 1 << 11;

// ============================================================================
// PAGE TABLE CONSTANTS
// ============================================================================

/// Entries per page table
pub const PAGE_TABLE_ENTRIES: usize = 512;

/// Page size (4K)
pub const PAGE_SIZE: usize = 4096;

// ============================================================================
// INDEX EXTRACTION HELPERS
// ============================================================================

/// Extracts PML4 index from virtual address.
#[inline]
pub const fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}

/// Extracts PDPT index from virtual address.
#[inline]
pub const fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}

/// Extracts PD index from virtual address.
#[inline]
pub const fn pd_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

/// Extracts PT index from virtual address.
#[inline]
pub const fn pt_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

/// Checks if a PTE is present.
#[inline]
pub const fn pte_is_present(entry: u64) -> bool {
    entry & PTE_PRESENT != 0
}

/// Extracts physical address from PTE.
#[inline]
pub const fn pte_address(entry: u64) -> u64 {
    entry & PTE_ADDR_MASK
}

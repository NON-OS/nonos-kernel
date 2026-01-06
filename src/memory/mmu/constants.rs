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
// ============================================================================
// PAGE TABLE ENTRY BITS
// ============================================================================
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE_PAGE: u64 = 1 << 7;
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NO_EXECUTE: u64 = 1u64 << 63;
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
// ============================================================================
// CR4 BITS
// ============================================================================
pub const CR4_PGE: u64 = 1 << 7;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
// ============================================================================
// CPUID BITS
// ============================================================================
pub const CPUID_FEATURES_LEAF: u32 = 0x07;
pub const CPUID_EBX_SMEP: u32 = 1 << 7;
pub const CPUID_EBX_SMAP: u32 = 1 << 20;
pub const CPUID_EXTENDED_LEAF: u32 = 0x8000_0001;
pub const CPUID_EDX_NX: u32 = 1 << 20;
// ============================================================================
// MSR ADDRESSES
// ============================================================================
pub const MSR_IA32_EFER: u32 = 0xC000_0080;
pub const EFER_NXE: u64 = 1 << 11;
// ============================================================================
// PAGE TABLE CONSTANTS
// ============================================================================
pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const PAGE_SIZE: usize = 4096;
// ============================================================================
// INDEX EXTRACTION HELPERS
// ============================================================================
#[inline]
pub const fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}

#[inline]
pub const fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}

#[inline]
pub const fn pd_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

#[inline]
pub const fn pt_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

#[inline]
pub const fn pte_is_present(entry: u64) -> bool {
    entry & PTE_PRESENT != 0
}

#[inline]
pub const fn pte_address(entry: u64) -> u64 {
    entry & PTE_ADDR_MASK
}

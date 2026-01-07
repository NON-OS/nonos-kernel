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
// PAGE SIZES
// ============================================================================
pub const PAGE_SIZE_4K: usize = 4096;
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;
pub const PAGE_SIZE: usize = PAGE_SIZE_4K;
// ============================================================================
// PAGE TABLE CONSTANTS
// ============================================================================
pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const PTE_SIZE: usize = 8;
pub const PAGE_TABLE_INDEX_MASK: u64 = 0x1FF;
pub const L4_INDEX_SHIFT: u64 = 39;
pub const L3_INDEX_SHIFT: u64 = 30;
pub const L2_INDEX_SHIFT: u64 = 21;
pub const L1_INDEX_SHIFT: u64 = 12;
// ============================================================================
// PTE FLAG BITS
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
pub const PTE_FLAGS_MASK: u64 = !PTE_ADDR_MASK;
// ============================================================================
// CR4 BITS
// ============================================================================
pub const CR4_PCIDE: u64 = 1 << 17;
// ============================================================================
// PAGE FAULT ERROR CODE BITS
// ============================================================================
pub const PF_PRESENT: u64 = 1 << 0;
pub const PF_WRITE: u64 = 1 << 1;
pub const PF_USER: u64 = 1 << 2;
pub const PF_RESERVED: u64 = 1 << 3;
pub const PF_INSTRUCTION: u64 = 1 << 4;
pub const PF_PROTECTION_KEY: u64 = 1 << 5;
pub const PF_SHADOW_STACK: u64 = 1 << 6;
// ============================================================================
// INDEX EXTRACTION HELPERS
// ============================================================================
#[inline]
pub const fn l4_index(va: u64) -> usize {
    ((va >> L4_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn l3_index(va: u64) -> usize {
    ((va >> L3_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn l2_index(va: u64) -> usize {
    ((va >> L2_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn l1_index(va: u64) -> usize {
    ((va >> L1_INDEX_SHIFT) & PAGE_TABLE_INDEX_MASK) as usize
}

#[inline]
pub const fn pte_is_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

#[inline]
pub const fn pte_address(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}

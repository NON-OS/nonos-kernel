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
// PAGE TABLE ENTRY FLAGS
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
pub const PTE_FLAGS_MASK: u64 = 0xFFF0_0000_0000_0FFF;
// ============================================================================
// PAGE TABLE ENTRY FLAG SHORTCUTS
// ============================================================================
pub const PTE_TABLE_FLAGS: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_USER;
pub const PTE_KERNEL_TABLE: u64 = PTE_PRESENT | PTE_WRITABLE;
// ============================================================================
// PAGE TABLE INDICES
// ============================================================================
pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const PML4_SHIFT: u64 = 39;
pub const PDPT_SHIFT: u64 = 30;
pub const PD_SHIFT: u64 = 21;
pub const PT_SHIFT: u64 = 12;
pub const INDEX_MASK: u64 = 0x1FF;
pub const PAGE_OFFSET_MASK: u64 = 0xFFF;
// ============================================================================
// PAGE SIZES
// ============================================================================
pub const PAGE_SIZE_4K: usize = 4096;
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;
// ============================================================================
// PAGE FAULT ERROR CODES
// ============================================================================
pub const PF_PRESENT: u64 = 1 << 0;
pub const PF_WRITE: u64 = 1 << 1;
pub const PF_USER: u64 = 1 << 2;
pub const PF_RESERVED: u64 = 1 << 3;
pub const PF_INSTRUCTION: u64 = 1 << 4;
pub const PF_PROTECTION_KEY: u64 = 1 << 5;
pub const PF_SHADOW_STACK: u64 = 1 << 6;
// ============================================================================
// CR0 BITS
// ============================================================================
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_WP_ENABLE_MASK: u32 = 0x10000;
pub const CR0_WP_DISABLE_MASK: u32 = 0xFFFE_FFFF;
// ============================================================================
// PERMISSION BITS (for PagePermissions)
// ============================================================================
pub const PERM_READ: u32 = 1 << 0;
pub const PERM_WRITE: u32 = 1 << 1;
pub const PERM_EXECUTE: u32 = 1 << 2;
pub const PERM_USER: u32 = 1 << 3;
pub const PERM_GLOBAL: u32 = 1 << 4;
pub const PERM_NO_CACHE: u32 = 1 << 5;
pub const PERM_WRITE_THROUGH: u32 = 1 << 6;
pub const PERM_COW: u32 = 1 << 7;
pub const PERM_DEMAND: u32 = 1 << 8;
pub const PERM_ZERO_FILL: u32 = 1 << 9;
pub const PERM_SHARED: u32 = 1 << 10;
pub const PERM_LOCKED: u32 = 1 << 11;
pub const PERM_DEVICE: u32 = 1 << 12;
// ============================================================================
// ADDRESS SPACE CONSTANTS
// ============================================================================
pub const KERNEL_ASID: u32 = 0;
pub const FIRST_USER_ASID: u32 = 1;
pub const KERNEL_PML4_START: usize = 256;
pub const KERNEL_PML4_COUNT: usize = 256;
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

#[inline]
pub const fn pml4_index(va: u64) -> usize {
    ((va >> PML4_SHIFT) & INDEX_MASK) as usize
}

#[inline]
pub const fn pdpt_index(va: u64) -> usize {
    ((va >> PDPT_SHIFT) & INDEX_MASK) as usize
}

#[inline]
pub const fn pd_index(va: u64) -> usize {
    ((va >> PD_SHIFT) & INDEX_MASK) as usize
}

#[inline]
pub const fn pt_index(va: u64) -> usize {
    ((va >> PT_SHIFT) & INDEX_MASK) as usize
}

#[inline]
pub const fn page_offset(va: u64) -> usize {
    (va & PAGE_OFFSET_MASK) as usize
}

#[inline]
pub const fn pte_is_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

#[inline]
pub const fn pte_is_huge(pte: u64) -> bool {
    pte & PTE_HUGE_PAGE != 0
}

#[inline]
pub const fn pte_address(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}

#[inline]
pub const fn page_align_down(addr: u64) -> u64 {
    addr & !PAGE_OFFSET_MASK
}

#[inline]
pub const fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_OFFSET_MASK) & !PAGE_OFFSET_MASK
}

#[inline]
pub const fn pages_needed(size: usize) -> usize {
    (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K
}

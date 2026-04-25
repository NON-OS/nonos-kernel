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

use crate::memory::layout::DIRECTMAP_BASE;
use crate::memory::paging::constants::*;

pub fn translate_with_cr3(cr3: u64, vaddr: usize) -> Option<usize> {
    let va = vaddr as u64;
    let l4_idx = pml4_index(va);
    let l3_idx = pdpt_index(va);
    let l2_idx = pd_index(va);
    let l1_idx = pt_index(va);
    let offset = page_offset(va);
    unsafe {
        let l4_table = &*((DIRECTMAP_BASE + cr3) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l4_table[l4_idx]) {
            return None;
        }
        let l3_pa = pte_address(l4_table[l4_idx]);
        let l3_table = &*((DIRECTMAP_BASE + l3_pa) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l3_table[l3_idx]) {
            return None;
        }
        if pte_is_huge(l3_table[l3_idx]) {
            let page_pa = pte_address(l3_table[l3_idx]);
            let huge_offset = va & 0x3FFF_FFFF;
            return Some((page_pa + huge_offset) as usize);
        }
        let l2_pa = pte_address(l3_table[l3_idx]);
        let l2_table = &*((DIRECTMAP_BASE + l2_pa) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l2_table[l2_idx]) {
            return None;
        }
        if pte_is_huge(l2_table[l2_idx]) {
            let page_pa = pte_address(l2_table[l2_idx]);
            let huge_offset = va & 0x1F_FFFF;
            return Some((page_pa + huge_offset) as usize);
        }
        let l1_pa = pte_address(l2_table[l2_idx]);
        let l1_table = &*((DIRECTMAP_BASE + l1_pa) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l1_table[l1_idx]) {
            return None;
        }
        let page_pa = pte_address(l1_table[l1_idx]);
        Some((page_pa + offset as u64) as usize)
    }
}

pub fn is_writable_with_cr3(cr3: u64, vaddr: usize) -> bool {
    let va = vaddr as u64;
    let l4_idx = pml4_index(va);
    let l3_idx = pdpt_index(va);
    let l2_idx = pd_index(va);
    let l1_idx = pt_index(va);
    unsafe {
        let l4_table = &*((DIRECTMAP_BASE + cr3) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l4_table[l4_idx]) {
            return false;
        }
        if !pte_is_writable(l4_table[l4_idx]) {
            return false;
        }
        let l3_pa = pte_address(l4_table[l4_idx]);
        let l3_table = &*((DIRECTMAP_BASE + l3_pa) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l3_table[l3_idx]) {
            return false;
        }
        if !pte_is_writable(l3_table[l3_idx]) {
            return false;
        }
        if pte_is_huge(l3_table[l3_idx]) {
            return true;
        }
        let l2_pa = pte_address(l3_table[l3_idx]);
        let l2_table = &*((DIRECTMAP_BASE + l2_pa) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l2_table[l2_idx]) {
            return false;
        }
        if !pte_is_writable(l2_table[l2_idx]) {
            return false;
        }
        if pte_is_huge(l2_table[l2_idx]) {
            return true;
        }
        let l1_pa = pte_address(l2_table[l2_idx]);
        let l1_table = &*((DIRECTMAP_BASE + l1_pa) as *const [u64; PAGE_TABLE_ENTRIES]);
        if !pte_is_present(l1_table[l1_idx]) {
            return false;
        }
        pte_is_writable(l1_table[l1_idx])
    }
}

pub fn phys_to_virt(phys: usize) -> usize {
    DIRECTMAP_BASE as usize + phys
}

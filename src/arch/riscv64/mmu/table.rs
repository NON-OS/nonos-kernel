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

use core::ptr::NonNull;

use super::attributes::{PageAttributes, PteFlags};
use super::sv39::Sv39;

#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        Self { entries: [0; 512] }
    }

    pub fn entry(&self, index: usize) -> u64 {
        self.entries[index]
    }

    pub fn set_entry(&mut self, index: usize, entry: u64) {
        self.entries[index] = entry;
    }

    pub fn clear_entry(&mut self, index: usize) {
        self.entries[index] = 0;
    }

    pub fn is_valid(&self, index: usize) -> bool {
        self.entries[index] & PteFlags::V != 0
    }

    pub fn is_leaf(&self, index: usize) -> bool {
        let entry = self.entries[index];
        (entry & PteFlags::V != 0) && (entry & (PteFlags::R | PteFlags::W | PteFlags::X) != 0)
    }

    pub fn is_branch(&self, index: usize) -> bool {
        let entry = self.entries[index];
        (entry & PteFlags::V != 0) && (entry & (PteFlags::R | PteFlags::W | PteFlags::X) == 0)
    }

    pub fn next_table_ppn(&self, index: usize) -> Option<u64> {
        if self.is_branch(index) {
            Some(Sv39::pte_ppn(self.entries[index]))
        } else {
            None
        }
    }

    pub fn page_ppn(&self, index: usize) -> Option<u64> {
        if self.is_leaf(index) {
            Some(Sv39::pte_ppn(self.entries[index]))
        } else {
            None
        }
    }

    pub fn set_branch(&mut self, index: usize, table_ppn: u64) {
        self.entries[index] = Sv39::make_pte(table_ppn, PteFlags::new().valid());
    }

    pub fn set_leaf(&mut self, index: usize, phys_ppn: u64, attrs: &PageAttributes) {
        self.entries[index] = Sv39::make_pte(phys_ppn, attrs.to_pte_flags());
    }

    pub fn as_ptr(&self) -> *const u64 {
        self.entries.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.entries.as_mut_ptr()
    }

    pub fn physical_address(&self) -> u64 {
        self.entries.as_ptr() as u64
    }

    pub fn ppn(&self) -> u64 {
        self.physical_address() >> 12
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PageTableAllocator {
    next_table: *mut PageTable,
    end: *mut PageTable,
}

impl PageTableAllocator {
    pub fn new(start: u64, size: usize) -> Self {
        let num_tables = size / core::mem::size_of::<PageTable>();
        Self {
            next_table: start as *mut PageTable,
            end: (start as *mut PageTable).wrapping_add(num_tables),
        }
    }

    pub fn alloc(&mut self) -> Option<NonNull<PageTable>> {
        if self.next_table >= self.end {
            return None;
        }

        let table = self.next_table;
        self.next_table = self.next_table.wrapping_add(1);

        unsafe {
            core::ptr::write_bytes(table, 0, 1);
        }

        NonNull::new(table)
    }

    pub fn remaining(&self) -> usize {
        (self.end as usize - self.next_table as usize) / core::mem::size_of::<PageTable>()
    }
}

pub fn walk_page_tables(root: &PageTable, va: usize) -> Option<(u64, usize)> {
    let mut table = root;

    for level in (0..3).rev() {
        let index = Sv39::vpn(va, level);
        let entry = table.entry(index);

        if entry & PteFlags::V == 0 {
            return None;
        }

        if entry & (PteFlags::R | PteFlags::W | PteFlags::X) != 0 {
            let ppn = Sv39::pte_ppn(entry);
            return Some((ppn, level));
        }

        let next_ppn = Sv39::pte_ppn(entry);
        table = unsafe { &*((next_ppn << 12) as *const PageTable) };
    }

    None
}

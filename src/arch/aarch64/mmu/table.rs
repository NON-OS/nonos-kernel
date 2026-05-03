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

use super::attributes::{PageAttributes, PTE_ADDR_MASK, PTE_PAGE, PTE_TABLE, PTE_VALID};
use super::granule::Granule;

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
        self.entries[index] & PTE_VALID != 0
    }

    pub fn is_table(&self, index: usize) -> bool {
        let entry = self.entries[index];
        (entry & PTE_VALID != 0) && (entry & PTE_TABLE != 0)
    }

    pub fn is_block(&self, index: usize) -> bool {
        let entry = self.entries[index];
        (entry & PTE_VALID != 0) && (entry & PTE_TABLE == 0)
    }

    pub fn table_address(&self, index: usize) -> Option<u64> {
        if self.is_table(index) {
            Some(self.entries[index] & PTE_ADDR_MASK)
        } else {
            None
        }
    }

    pub fn block_address(&self, index: usize) -> Option<u64> {
        if self.is_block(index) {
            Some(self.entries[index] & PTE_ADDR_MASK)
        } else {
            None
        }
    }

    pub fn set_table(&mut self, index: usize, table_addr: u64) {
        self.entries[index] = (table_addr & PTE_ADDR_MASK) | PTE_TABLE | PTE_VALID;
    }

    pub fn set_block(&mut self, index: usize, phys_addr: u64, attrs: &PageAttributes) {
        self.entries[index] = (phys_addr & PTE_ADDR_MASK) | attrs.to_descriptor_bits() | PTE_VALID;
    }

    pub fn set_page(&mut self, index: usize, phys_addr: u64, attrs: &PageAttributes) {
        self.entries[index] =
            (phys_addr & PTE_ADDR_MASK) | attrs.to_descriptor_bits() | PTE_PAGE | PTE_VALID;
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

pub fn walk_page_tables(root: &PageTable, virt: u64, granule: Granule) -> Option<(u64, usize)> {
    let mut table = root;
    let levels = granule.levels();

    for level in 0..levels {
        let index = granule.index_at_level(virt, level);
        let entry = table.entry(index);

        if entry & PTE_VALID == 0 {
            return None;
        }

        if level == levels - 1 || (entry & PTE_TABLE == 0) {
            let addr = entry & PTE_ADDR_MASK;
            return Some((addr, level));
        }

        let next_table_addr = entry & PTE_ADDR_MASK;
        table = unsafe { &*(next_table_addr as *const PageTable) };
    }

    None
}

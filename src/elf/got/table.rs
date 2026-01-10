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

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;
use x86_64::VirtAddr;

use crate::elf::errors::{ElfError, ElfResult};

pub const GOT_ENTRY_SIZE: usize = 8;
pub const PLT_ENTRY_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotEntryType {
    Null,
    Dynamic,
    PltResolver,
    LinkMap,
    Symbol(usize),
}

#[derive(Debug, Clone)]
pub struct GotEntry {
    pub index: usize,
    pub address: VirtAddr,
    pub value: u64,
    pub entry_type: GotEntryType,
    pub resolved: bool,
}

impl GotEntry {
    pub fn new(index: usize, address: VirtAddr, value: u64, entry_type: GotEntryType) -> Self {
        Self { index, address, value, entry_type, resolved: false }
    }

    pub fn resolve(&mut self, target: u64) {
        self.value = target;
        self.resolved = true;
    }
}

pub struct GlobalOffsetTable {
    base: VirtAddr,
    entry_count: usize,
    entries: Vec<GotEntry>,
    plt_base: Option<VirtAddr>,
    plt_entry_count: usize,
}

impl GlobalOffsetTable {
    pub fn new(base: VirtAddr, size: usize) -> Self {
        let entry_count = size / GOT_ENTRY_SIZE;
        Self {
            base,
            entry_count,
            entries: Vec::with_capacity(entry_count),
            plt_base: None,
            plt_entry_count: 0,
        }
    }

    pub fn with_plt(mut self, plt_base: VirtAddr, plt_size: usize) -> Self {
        self.plt_base = Some(plt_base);
        self.plt_entry_count = plt_size / PLT_ENTRY_SIZE;
        self
    }

    pub fn initialize(&mut self) -> ElfResult<()> {
        self.entries.clear();

        for i in 0..self.entry_count {
            let addr = VirtAddr::new(self.base.as_u64() + (i * GOT_ENTRY_SIZE) as u64);

            // SAFETY: Caller ensures GOT memory is valid and mapped
            let value = unsafe { ptr::read(addr.as_u64() as *const u64) };

            let entry_type = match i {
                0 => GotEntryType::Dynamic,
                1 => GotEntryType::LinkMap,
                2 => GotEntryType::PltResolver,
                _ => GotEntryType::Symbol(i - 3),
            };

            self.entries.push(GotEntry::new(i, addr, value, entry_type));
        }

        Ok(())
    }

    pub fn get_entry(&self, index: usize) -> Option<&GotEntry> {
        self.entries.get(index)
    }

    pub fn get_entry_mut(&mut self, index: usize) -> Option<&mut GotEntry> {
        self.entries.get_mut(index)
    }

    pub fn read_entry(&self, index: usize) -> ElfResult<u64> {
        if index >= self.entry_count {
            return Err(ElfError::InvalidIndex);
        }

        let addr = self.base.as_u64() + (index * GOT_ENTRY_SIZE) as u64;

        // SAFETY: Index is bounds-checked and GOT memory is valid
        unsafe { Ok(ptr::read(addr as *const u64)) }
    }

    pub fn write_entry(&mut self, index: usize, value: u64) -> ElfResult<()> {
        if index >= self.entry_count {
            return Err(ElfError::InvalidIndex);
        }

        let addr = self.base.as_u64() + (index * GOT_ENTRY_SIZE) as u64;

        // SAFETY: Index is bounds-checked and GOT memory is valid
        unsafe {
            ptr::write(addr as *mut u64, value);
        }

        if let Some(entry) = self.entries.get_mut(index) {
            entry.resolve(value);
        }

        Ok(())
    }

    pub fn resolve_symbol(&mut self, index: usize, target: VirtAddr) -> ElfResult<()> {
        self.write_entry(index, target.as_u64())
    }

    pub fn set_dynamic(&mut self, dynamic_addr: VirtAddr) -> ElfResult<()> {
        self.write_entry(0, dynamic_addr.as_u64())
    }

    pub fn set_link_map(&mut self, link_map_addr: VirtAddr) -> ElfResult<()> {
        self.write_entry(1, link_map_addr.as_u64())
    }

    pub fn set_plt_resolver(&mut self, resolver_addr: VirtAddr) -> ElfResult<()> {
        self.write_entry(2, resolver_addr.as_u64())
    }

    pub fn plt_entry_address(&self, plt_index: usize) -> Option<VirtAddr> {
        self.plt_base.and_then(|base| {
            if plt_index < self.plt_entry_count {
                Some(VirtAddr::new(base.as_u64() + (plt_index * PLT_ENTRY_SIZE) as u64))
            } else {
                None
            }
        })
    }

    pub fn got_entry_for_plt(&self, plt_index: usize) -> Option<usize> {
        if plt_index < self.plt_entry_count {
            Some(plt_index + 3)
        } else {
            None
        }
    }

    pub fn base(&self) -> VirtAddr {
        self.base
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn plt_entry_count(&self) -> usize {
        self.plt_entry_count
    }

    pub fn unresolved_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.resolved).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = &GotEntry> {
        self.entries.iter()
    }
}

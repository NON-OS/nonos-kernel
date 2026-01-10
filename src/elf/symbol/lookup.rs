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

use alloc::string::String;
use core::ptr;
use x86_64::VirtAddr;

use crate::elf::types::Symbol;

pub struct SymbolLookup {
    symtab: VirtAddr,
    strtab: VirtAddr,
    strtab_size: usize,
    sym_count: usize,
    base_addr: VirtAddr,
}

impl SymbolLookup {
    pub fn new(
        symtab: VirtAddr,
        strtab: VirtAddr,
        strtab_size: usize,
        sym_count: usize,
        base_addr: VirtAddr,
    ) -> Self {
        Self {
            symtab,
            strtab,
            strtab_size,
            sym_count,
            base_addr,
        }
    }

    pub fn find_by_name(&self, name: &str) -> Option<(VirtAddr, u64)> {
        for i in 1..self.sym_count {
            // SAFETY: Caller ensures symtab is valid
            unsafe {
                let sym_ptr = (self.symtab.as_u64() + (i * Symbol::SIZE) as u64) as *const Symbol;
                let sym = ptr::read(sym_ptr);

                if sym.st_shndx == 0 || sym.st_name as usize >= self.strtab_size {
                    continue;
                }

                let sym_name = self.read_name(sym.st_name as usize);
                if sym_name == name {
                    let addr = self.base_addr + sym.st_value;
                    return Some((addr, sym.st_size));
                }
            }
        }
        None
    }

    pub fn find_by_index(&self, index: usize) -> Option<(String, VirtAddr, u64)> {
        if index == 0 || index >= self.sym_count {
            return None;
        }

        // SAFETY: Index is bounds-checked
        unsafe {
            let sym_ptr = (self.symtab.as_u64() + (index * Symbol::SIZE) as u64) as *const Symbol;
            let sym = ptr::read(sym_ptr);

            if sym.st_shndx == 0 {
                return None;
            }

            let name = if (sym.st_name as usize) < self.strtab_size {
                self.read_name(sym.st_name as usize)
            } else {
                String::new()
            };

            let addr = self.base_addr + sym.st_value;
            Some((name, addr, sym.st_size))
        }
    }

    pub fn find_containing(&self, addr: VirtAddr) -> Option<(String, VirtAddr, u64)> {
        let target = addr.as_u64();
        let mut best_match: Option<(String, VirtAddr, u64)> = None;
        let mut best_distance = u64::MAX;
        for i in 1..self.sym_count {
            // SAFETY: Caller ensures symtab is valid
            unsafe {
                let sym_ptr = (self.symtab.as_u64() + (i * Symbol::SIZE) as u64) as *const Symbol;
                let sym = ptr::read(sym_ptr);

                if sym.st_shndx == 0 {
                    continue;
                }

                let sym_addr = self.base_addr.as_u64() + sym.st_value;
                let sym_end = sym_addr + sym.st_size;
                if target >= sym_addr && target < sym_end {
                    let distance = target - sym_addr;
                    if distance < best_distance {
                        best_distance = distance;
                        let name = if (sym.st_name as usize) < self.strtab_size {
                            self.read_name(sym.st_name as usize)
                        } else {
                            String::new()
                        };
                        best_match = Some((name, VirtAddr::new(sym_addr), sym.st_size));
                    }
                }
            }
        }

        best_match
    }

    fn read_name(&self, offset: usize) -> String {
        // SAFETY: Caller ensures strtab is valid
        unsafe {
            let ptr = (self.strtab.as_u64() + offset as u64) as *const u8;
            let max_len = self.strtab_size.saturating_sub(offset).min(256);
            let mut name = String::new();
            for i in 0..max_len {
                let c = *ptr.add(i);
                if c == 0 {
                    break;
                }
                name.push(c as char);
            }
            name
        }
    }

    pub fn symbol_count(&self) -> usize {
        self.sym_count
    }
}

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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use x86_64::VirtAddr;

use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::types::{symbol_bind, symbol_type, Symbol};

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub name: String,
    pub address: VirtAddr,
    pub size: u64,
    pub binding: u8,
    pub sym_type: u8,
    pub library_id: usize,
}

impl ResolvedSymbol {
    pub fn is_function(&self) -> bool {
        self.sym_type == symbol_type::STT_FUNC
    }

    pub fn is_object(&self) -> bool {
        self.sym_type == symbol_type::STT_OBJECT
    }

    pub fn is_global(&self) -> bool {
        self.binding == symbol_bind::STB_GLOBAL
    }

    pub fn is_weak(&self) -> bool {
        self.binding == symbol_bind::STB_WEAK
    }
}

pub struct SymbolResolver {
    global_symbols: BTreeMap<String, ResolvedSymbol>,
    weak_symbols: BTreeMap<String, ResolvedSymbol>,
    library_order: Vec<usize>,
}

impl SymbolResolver {
    pub fn new() -> Self {
        Self {
            global_symbols: BTreeMap::new(),
            weak_symbols: BTreeMap::new(),
            library_order: Vec::new(),
        }
    }

    pub fn add_library(&mut self, library_id: usize) {
        if !self.library_order.contains(&library_id) {
            self.library_order.push(library_id);
        }
    }

    pub fn register_symbol(&mut self, symbol: ResolvedSymbol) {
        if symbol.is_weak() {
            if !self.global_symbols.contains_key(&symbol.name) {
                self.weak_symbols.insert(symbol.name.clone(), symbol);
            }
        } else if symbol.is_global() {
            self.weak_symbols.remove(&symbol.name);
            self.global_symbols.insert(symbol.name.clone(), symbol);
        }
    }

    pub fn resolve(&self, name: &str) -> Option<&ResolvedSymbol> {
        self.global_symbols
            .get(name)
            .or_else(|| self.weak_symbols.get(name))
    }

    pub fn resolve_address(&self, name: &str) -> Option<VirtAddr> {
        self.resolve(name).map(|s| s.address)
    }

    pub fn parse_symbols(
        &mut self,
        symtab: VirtAddr,
        strtab: VirtAddr,
        strtab_size: usize,
        sym_count: usize,
        base_addr: VirtAddr,
        library_id: usize,
    ) -> ElfResult<usize> {
        let mut registered = 0;

        for i in 1..sym_count {
            // SAFETY: Caller ensures symtab and strtab are valid
            unsafe {
                let sym_ptr = (symtab.as_u64() + (i * Symbol::SIZE) as u64) as *const Symbol;
                let sym = ptr::read(sym_ptr);

                if sym.st_shndx == 0 {
                    continue;
                }

                let binding = sym.st_info >> 4;
                let sym_type = sym.st_info & 0x0F;

                if binding != symbol_bind::STB_GLOBAL && binding != symbol_bind::STB_WEAK {
                    continue;
                }

                if sym.st_name as usize >= strtab_size {
                    continue;
                }

                let name_ptr = (strtab.as_u64() + sym.st_name as u64) as *const u8;
                let name = read_symbol_name(name_ptr, strtab_size - sym.st_name as usize);

                if name.is_empty() {
                    continue;
                }

                let address = if sym_type == symbol_type::STT_TLS {
                    VirtAddr::new(sym.st_value)
                } else {
                    base_addr + sym.st_value
                };

                let resolved = ResolvedSymbol {
                    name,
                    address,
                    size: sym.st_size,
                    binding,
                    sym_type,
                    library_id,
                };

                self.register_symbol(resolved);
                registered += 1;
            }
        }

        self.add_library(library_id);
        Ok(registered)
    }

    pub fn symbol_count(&self) -> usize {
        self.global_symbols.len() + self.weak_symbols.len()
    }

    pub fn global_count(&self) -> usize {
        self.global_symbols.len()
    }

    pub fn weak_count(&self) -> usize {
        self.weak_symbols.len()
    }

    pub fn library_count(&self) -> usize {
        self.library_order.len()
    }

    pub fn clear(&mut self) {
        self.global_symbols.clear();
        self.weak_symbols.clear();
        self.library_order.clear();
    }
}

impl Default for SymbolResolver {
    fn default() -> Self {
        Self::new()
    }
}

unsafe fn read_symbol_name(ptr: *const u8, max_len: usize) -> String {
    let mut name = String::new();
    for i in 0..max_len.min(256) {
        let c = *ptr.add(i);
        if c == 0 {
            break;
        }
        name.push(c as char);
    }
    name
}

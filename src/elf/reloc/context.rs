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
use x86_64::VirtAddr;

use crate::elf::types::SymbolEntry;

pub struct RelocationContext<'a> {
    pub symbol_table: Option<VirtAddr>,
    pub string_table: Option<VirtAddr>,
    pub string_table_size: usize,
    pub got_base: Option<VirtAddr>,
    pub symbol_cache: &'a BTreeMap<String, VirtAddr>,
}

impl<'a> RelocationContext<'a> {
    pub fn empty(cache: &'a BTreeMap<String, VirtAddr>) -> Self {
        Self {
            symbol_table: None,
            string_table: None,
            string_table_size: 0,
            got_base: None,
            symbol_cache: cache,
        }
    }

    pub fn resolve_symbol(&self, sym_index: u32, base_addr: VirtAddr) -> Option<u64> {
        if sym_index == 0 {
            return Some(0);
        }

        let symtab = self.symbol_table?;

        // SAFETY: We trust the symbol table address from ELF parsing
        unsafe {
            let sym_ptr = (symtab.as_u64() + (sym_index as u64) * SymbolEntry::SIZE as u64)
                as *const SymbolEntry;
            let sym = core::ptr::read(sym_ptr);
            let sym_bind = sym.st_info >> 4;
            if sym.st_shndx == 0 {
                if let Some(strtab) = self.string_table {
                    if (sym.st_name as usize) < self.string_table_size {
                        let name_ptr = (strtab.as_u64() + sym.st_name as u64) as *const u8;
                        let name = read_null_terminated_string(name_ptr, 256);
                        if let Some(addr) = self.symbol_cache.get(&name) {
                            return Some(addr.as_u64());
                        }
                    }
                }

                if sym_bind == 2 {
                    return Some(0);
                }

                return None;
            }

            let sym_type = sym.st_info & 0x0F;
            if sym_type == 0 || sym.st_shndx == 0xFFF1 {
                Some(sym.st_value)
            } else {
                Some(base_addr.as_u64() + sym.st_value)
            }
        }
    }
}

pub unsafe fn read_null_terminated_string(ptr: *const u8, max_len: usize) -> String {
    // SAFETY: Caller ensures ptr is valid for up to max_len bytes
    let mut result = String::new();
    for i in 0..max_len {
        let byte = *ptr.add(i);
        if byte == 0 {
            break;
        }
        result.push(byte as char);
    }
    result
}

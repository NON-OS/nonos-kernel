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

use alloc::{string::String, vec::Vec};
use x86_64::VirtAddr;

#[derive(Debug, Clone)]
pub struct DynLinkInfo {
    pub needed_libraries: Vec<String>,
    pub symtab: Option<VirtAddr>,
    pub strtab: Option<VirtAddr>,
    pub strtab_size: usize,
    pub sym_count: usize,
    pub rela_table: Option<VirtAddr>,
    pub rela_size: usize,
    pub plt_relocations: Option<VirtAddr>,
    pub plt_rela_size: usize,
    pub init: Option<VirtAddr>,
    pub fini: Option<VirtAddr>,
    pub init_array: Option<(VirtAddr, usize)>,
    pub fini_array: Option<(VirtAddr, usize)>,
}

impl DynLinkInfo {
    pub fn new() -> Self {
        Self {
            needed_libraries: Vec::new(),
            symtab: None,
            strtab: None,
            strtab_size: 0,
            sym_count: 0,
            rela_table: None,
            rela_size: 0,
            plt_relocations: None,
            plt_rela_size: 0,
            init: None,
            fini: None,
            init_array: None,
            fini_array: None,
        }
    }

    pub fn needs_libraries(&self) -> bool {
        !self.needed_libraries.is_empty()
    }

    pub fn library_count(&self) -> usize {
        self.needed_libraries.len()
    }

    pub fn has_relocations(&self) -> bool {
        self.rela_table.is_some() || self.plt_relocations.is_some()
    }

    pub fn has_symbols(&self) -> bool {
        self.symtab.is_some()
    }

    pub fn has_strings(&self) -> bool {
        self.strtab.is_some() && self.strtab_size > 0
    }

    pub fn has_init(&self) -> bool {
        self.init.is_some() || self.init_array.is_some()
    }

    pub fn has_fini(&self) -> bool {
        self.fini.is_some() || self.fini_array.is_some()
    }

    pub fn rela_count(&self) -> usize {
        self.rela_size / 24
    }

    pub fn plt_rela_count(&self) -> usize {
        self.plt_rela_size / 24
    }

    pub fn total_relocation_count(&self) -> usize {
        self.rela_count() + self.plt_rela_count()
    }

    pub fn add_needed(&mut self, name: String) {
        self.needed_libraries.push(name);
    }

    pub fn needs_library(&self, name: &str) -> bool {
        self.needed_libraries.iter().any(|lib| lib == name)
    }

    pub fn string_table_end(&self) -> Option<VirtAddr> {
        self.strtab.map(|addr| addr + self.strtab_size as u64)
    }

    pub fn is_empty(&self) -> bool {
        self.needed_libraries.is_empty()
            && self.symtab.is_none()
            && self.rela_table.is_none()
            && self.plt_relocations.is_none()
            && self.init.is_none()
            && self.fini.is_none()
            && self.init_array.is_none()
            && self.fini_array.is_none()
    }
}

impl Default for DynLinkInfo {
    fn default() -> Self {
        Self::new()
    }
}

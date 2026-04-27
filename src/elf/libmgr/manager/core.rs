// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::types::LoadedLibrary;
use crate::elf::symbol::SymbolResolver;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub struct LibraryManager {
    pub(super) libraries: BTreeMap<usize, LoadedLibrary>,
    pub(super) name_index: BTreeMap<String, usize>,
    pub(super) soname_index: BTreeMap<String, usize>,
    pub(super) addr_index: BTreeMap<u64, usize>,
    pub(super) symbol_resolver: SymbolResolver,
    pub(super) load_order: Vec<usize>,
}

impl LibraryManager {
    pub fn new() -> Self {
        Self {
            libraries: BTreeMap::new(),
            name_index: BTreeMap::new(),
            soname_index: BTreeMap::new(),
            addr_index: BTreeMap::new(),
            symbol_resolver: SymbolResolver::new(),
            load_order: Vec::new(),
        }
    }
}

impl Default for LibraryManager {
    fn default() -> Self {
        Self::new()
    }
}

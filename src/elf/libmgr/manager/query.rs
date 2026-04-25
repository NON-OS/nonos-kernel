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

use super::core::LibraryManager;
use super::types::LoadedLibrary;
use crate::elf::symbol::SymbolResolver;
use x86_64::VirtAddr;

impl LibraryManager {
    pub fn get(&self, id: usize) -> Option<&LoadedLibrary> {
        self.libraries.get(&id)
    }
    pub fn get_mut(&mut self, id: usize) -> Option<&mut LoadedLibrary> {
        self.libraries.get_mut(&id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&LoadedLibrary> {
        self.name_index
            .get(name)
            .or_else(|| self.soname_index.get(name))
            .and_then(|id| self.libraries.get(id))
    }

    pub fn get_by_addr(&self, addr: VirtAddr) -> Option<&LoadedLibrary> {
        for library in self.libraries.values() {
            let base = library.base_addr().as_u64();
            let end = base + library.image.memory_size as u64;
            if addr.as_u64() >= base && addr.as_u64() < end {
                return Some(library);
            }
        }
        None
    }

    pub fn resolve_symbol(&self, name: &str) -> Option<VirtAddr> {
        self.symbol_resolver.resolve_address(name)
    }
    pub fn symbol_resolver(&self) -> &SymbolResolver {
        &self.symbol_resolver
    }
    pub fn count(&self) -> usize {
        self.libraries.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = &LoadedLibrary> {
        self.libraries.values()
    }
    pub fn load_order(&self) -> &[usize] {
        &self.load_order
    }
}

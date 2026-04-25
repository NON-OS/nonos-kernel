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
use crate::elf::embedded::EmbeddedLibraryRegistry;
use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::loader::ElfLoader;
use alloc::string::String;

impl LibraryManager {
    pub fn load(
        &mut self,
        loader: &mut ElfLoader,
        name: String,
        elf_data: &[u8],
    ) -> ElfResult<usize> {
        if self.name_index.contains_key(&name) {
            let id = self.name_index[&name];
            if let Some(lib) = self.libraries.get_mut(&id) {
                lib.acquire();
            }
            return Ok(id);
        }
        let image = loader.load_library(elf_data)?;
        let library = LoadedLibrary::new(name.clone(), image);
        let id = library.id;
        let base_addr = library.base_addr().as_u64();
        self.name_index.insert(name, id);
        self.addr_index.insert(base_addr, id);
        self.load_order.push(id);
        self.libraries.insert(id, library);
        Ok(id)
    }

    pub fn load_from_embedded(
        &mut self,
        registry: &EmbeddedLibraryRegistry,
        loader: &mut ElfLoader,
        name: &str,
    ) -> ElfResult<usize> {
        if self.name_index.contains_key(name) {
            let id = self.name_index[name];
            if let Some(lib) = self.libraries.get_mut(&id) {
                lib.acquire();
            }
            return Ok(id);
        }
        let embedded = registry.get(name).ok_or(ElfError::LibraryNotFound)?;
        let image = loader.load_library(embedded.data)?;
        let mut library = LoadedLibrary::new(embedded.name.clone(), image);
        if let Some(ref soname) = embedded.soname {
            library = library.with_soname(soname.clone());
            self.soname_index.insert(soname.clone(), library.id);
        }
        let id = library.id;
        let base_addr = library.base_addr().as_u64();
        self.name_index.insert(embedded.name.clone(), id);
        self.addr_index.insert(base_addr, id);
        self.load_order.push(id);
        self.libraries.insert(id, library);
        Ok(id)
    }
}

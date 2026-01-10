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
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::VirtAddr;

use crate::elf::cache::ImageCache;
use crate::elf::embedded::EmbeddedLibraryRegistry;
use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::fini::FiniArrayRunner;
use crate::elf::got::GlobalOffsetTable;
use crate::elf::hash::DualHashLookup;
use crate::elf::init::InitArrayRunner;
use crate::elf::loader::{ElfImage, ElfLoader};
use crate::elf::symbol::SymbolResolver;

static NEXT_LIBRARY_ID: AtomicUsize = AtomicUsize::new(1);

fn next_library_id() -> usize {
    NEXT_LIBRARY_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryState {
    Loading,
    Relocating,
    Initializing,
    Ready,
    Finalizing,
    Unloaded,
}

#[derive(Debug)]
pub struct LoadedLibrary {
    pub id: usize,
    pub name: String,
    pub soname: Option<String>,
    pub image: ElfImage,
    pub state: LibraryState,
    pub ref_count: usize,
    pub dependencies: Vec<usize>,
    pub dependents: Vec<usize>,
    pub init_called: bool,
    pub fini_called: bool,
}

impl LoadedLibrary {
    pub fn new(name: String, image: ElfImage) -> Self {
        Self {
            id: next_library_id(),
            name,
            soname: None,
            image,
            state: LibraryState::Loading,
            ref_count: 1,
            dependencies: Vec::new(),
            dependents: Vec::new(),
            init_called: false,
            fini_called: false,
        }
    }

    pub fn with_soname(mut self, soname: String) -> Self {
        self.soname = Some(soname);
        self
    }

    pub fn acquire(&mut self) {
        self.ref_count += 1;
    }

    pub fn release(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }

    pub fn is_ready(&self) -> bool {
        self.state == LibraryState::Ready
    }

    pub fn base_addr(&self) -> VirtAddr {
        self.image.base_addr
    }

    pub fn entry_point(&self) -> VirtAddr {
        self.image.entry_point
    }
}

pub struct LibraryManager {
    libraries: BTreeMap<usize, LoadedLibrary>,
    name_index: BTreeMap<String, usize>,
    soname_index: BTreeMap<String, usize>,
    addr_index: BTreeMap<u64, usize>,
    symbol_resolver: SymbolResolver,
    load_order: Vec<usize>,
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

    pub fn relocate(&mut self, id: usize) -> ElfResult<()> {
        let library = self.libraries.get_mut(&id).ok_or(ElfError::LibraryNotFound)?;

        if library.state != LibraryState::Loading {
            return Ok(());
        }

        library.state = LibraryState::Relocating;

        if let Some(ref dynlink) = library.image.dynlink_info {
            self.symbol_resolver.parse_symbols(
                dynlink.symtab,
                dynlink.strtab,
                dynlink.strtab_size,
                dynlink.sym_count,
                library.image.base_addr,
                id,
            )?;
        }

        library.state = LibraryState::Ready;
        Ok(())
    }

    pub fn initialize(&mut self, id: usize) -> ElfResult<()> {
        let library = self.libraries.get_mut(&id).ok_or(ElfError::LibraryNotFound)?;

        if library.init_called {
            return Ok(());
        }

        if library.state != LibraryState::Ready {
            return Err(ElfError::InvalidState);
        }

        library.state = LibraryState::Initializing;

        if let Some(ref dynlink) = library.image.dynlink_info {
            let mut runner = InitArrayRunner::new();

            if let Some(init_addr) = dynlink.init {
                runner = runner.with_init_fn(init_addr);
            }

            if let Some((addr, size)) = dynlink.init_array {
                runner = runner.with_init_array(crate::elf::init::InitArrayInfo::new(addr, size));
            }

            runner.run_all()?;
        }

        library.init_called = true;
        library.state = LibraryState::Ready;
        Ok(())
    }

    pub fn finalize(&mut self, id: usize) -> ElfResult<()> {
        let library = self.libraries.get_mut(&id).ok_or(ElfError::LibraryNotFound)?;

        if library.fini_called {
            return Ok(());
        }

        library.state = LibraryState::Finalizing;

        if let Some(ref dynlink) = library.image.dynlink_info {
            let mut runner = FiniArrayRunner::new();

            if let Some((addr, size)) = dynlink.fini_array {
                runner = runner.with_fini_array(crate::elf::fini::FiniArrayInfo::new(addr, size));
            }

            if let Some(fini_addr) = dynlink.fini {
                runner = runner.with_fini_fn(fini_addr);
            }

            runner.run_all()?;
        }

        library.fini_called = true;
        library.state = LibraryState::Unloaded;
        Ok(())
    }

    pub fn unload(&mut self, id: usize) -> ElfResult<()> {
        let should_unload = {
            let library = self.libraries.get_mut(&id).ok_or(ElfError::LibraryNotFound)?;
            library.release()
        };

        if should_unload {
            self.finalize(id)?;

            if let Some(library) = self.libraries.remove(&id) {
                self.name_index.remove(&library.name);
                if let Some(ref soname) = library.soname {
                    self.soname_index.remove(soname);
                }
                self.addr_index.remove(&library.base_addr().as_u64());
                self.load_order.retain(|&i| i != id);
            }
        }

        Ok(())
    }

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

    pub fn initialize_all(&mut self) -> ElfResult<usize> {
        let ids: Vec<usize> = self.load_order.clone();
        let mut count = 0;

        for id in ids {
            self.initialize(id)?;
            count += 1;
        }

        Ok(count)
    }

    pub fn finalize_all(&mut self) -> ElfResult<usize> {
        let ids: Vec<usize> = self.load_order.iter().rev().copied().collect();
        let mut count = 0;

        for id in ids {
            self.finalize(id)?;
            count += 1;
        }

        Ok(count)
    }
}

impl Default for LibraryManager {
    fn default() -> Self {
        Self::new()
    }
}

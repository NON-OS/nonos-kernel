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
use alloc::vec::Vec;
use x86_64::VirtAddr;

use super::registry::{EmbeddedLibrary, EmbeddedLibraryRegistry};
use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::loader::{ElfImage, ElfLoader};

pub struct EmbeddedLibraryLoader<'a> {
    registry: &'a EmbeddedLibraryRegistry,
    elf_loader: &'a mut ElfLoader,
    loaded_images: Vec<LoadedEmbeddedLibrary>,
}

#[derive(Debug)]
pub struct LoadedEmbeddedLibrary {
    pub name: String,
    pub image: ElfImage,
    pub load_order: usize,
}

impl<'a> EmbeddedLibraryLoader<'a> {
    pub fn new(registry: &'a EmbeddedLibraryRegistry, elf_loader: &'a mut ElfLoader) -> Self {
        Self { registry, elf_loader, loaded_images: Vec::new() }
    }

    pub fn load(&mut self, name: &str) -> ElfResult<&LoadedEmbeddedLibrary> {
        if let Some(idx) = self.find_loaded(name) {
            return Ok(&self.loaded_images[idx]);
        }

        let library = self.registry.get(name).ok_or(ElfError::LibraryNotFound)?;

        let deps = self.registry.resolve_dependencies(library)?;

        for dep in deps {
            if self.find_loaded(&dep.name).is_none() {
                self.load_single(dep)?;
            }
        }

        let idx = self.load_single(library)?;
        Ok(&self.loaded_images[idx])
    }

    fn load_single(&mut self, library: &EmbeddedLibrary) -> ElfResult<usize> {
        let image = self.elf_loader.load_library(library.data)?;
        let load_order = self.loaded_images.len();

        self.loaded_images.push(LoadedEmbeddedLibrary {
            name: library.name.clone(),
            image,
            load_order,
        });

        Ok(load_order)
    }

    fn find_loaded(&self, name: &str) -> Option<usize> {
        self.loaded_images.iter().position(|l| l.name == name)
    }

    pub fn get_loaded(&self, name: &str) -> Option<&LoadedEmbeddedLibrary> {
        self.find_loaded(name).map(|idx| &self.loaded_images[idx])
    }

    pub fn loaded_count(&self) -> usize {
        self.loaded_images.len()
    }

    pub fn loaded_libraries(&self) -> &[LoadedEmbeddedLibrary] {
        &self.loaded_images
    }

    pub fn load_all_dependencies(&mut self, library_name: &str) -> ElfResult<Vec<String>> {
        let library = self.registry.get(library_name).ok_or(ElfError::LibraryNotFound)?;

        let deps = self.registry.resolve_dependencies(library)?;
        let mut loaded_names = Vec::new();

        for dep in deps {
            if self.find_loaded(&dep.name).is_none() {
                self.load_single(dep)?;
                loaded_names.push(dep.name.clone());
            }
        }

        Ok(loaded_names)
    }

    pub fn unload(&mut self, name: &str) -> ElfResult<()> {
        if let Some(idx) = self.find_loaded(name) {
            self.loaded_images.remove(idx);
            Ok(())
        } else {
            Err(ElfError::LibraryNotFound)
        }
    }

    pub fn unload_all(&mut self) {
        self.loaded_images.clear();
    }
}

pub fn load_embedded_library(
    registry: &EmbeddedLibraryRegistry,
    loader: &mut ElfLoader,
    name: &str,
) -> ElfResult<ElfImage> {
    let library = registry.get(name).ok_or(ElfError::LibraryNotFound)?;
    loader.load_library(library.data)
}

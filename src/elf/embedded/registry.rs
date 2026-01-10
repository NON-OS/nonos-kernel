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
use x86_64::VirtAddr;

use crate::elf::errors::{ElfError, ElfResult};

#[derive(Debug, Clone)]
pub struct EmbeddedLibrary {
    pub name: String,
    pub soname: Option<String>,
    pub data: &'static [u8],
    pub version: LibraryVersion,
    pub dependencies: Vec<String>,
}

impl EmbeddedLibrary {
    pub const fn new(name: &'static str, data: &'static [u8]) -> Self {
        Self {
            name: String::new(),
            soname: None,
            data,
            version: LibraryVersion::new(0, 0, 0),
            dependencies: Vec::new(),
        }
    }

    pub fn with_name(data: &'static [u8], name: String) -> Self {
        Self {
            name,
            soname: None,
            data,
            version: LibraryVersion::new(0, 0, 0),
            dependencies: Vec::new(),
        }
    }

    pub fn with_soname(mut self, soname: String) -> Self {
        self.soname = Some(soname);
        self
    }

    pub fn with_version(mut self, version: LibraryVersion) -> Self {
        self.version = version;
        self
    }

    pub fn with_dependencies(mut self, deps: Vec<String>) -> Self {
        self.dependencies = deps;
        self
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibraryVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl LibraryVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn is_compatible(&self, required: &LibraryVersion) -> bool {
        if self.major != required.major {
            return false;
        }
        if self.minor < required.minor {
            return false;
        }
        true
    }
}

pub struct EmbeddedLibraryRegistry {
    libraries: BTreeMap<String, EmbeddedLibrary>,
    soname_index: BTreeMap<String, String>,
}

impl EmbeddedLibraryRegistry {
    pub fn new() -> Self {
        Self { libraries: BTreeMap::new(), soname_index: BTreeMap::new() }
    }

    pub fn register(&mut self, library: EmbeddedLibrary) -> ElfResult<()> {
        if self.libraries.contains_key(&library.name) {
            return Err(ElfError::LibraryAlreadyLoaded);
        }

        if let Some(ref soname) = library.soname {
            self.soname_index.insert(soname.clone(), library.name.clone());
        }

        self.libraries.insert(library.name.clone(), library);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&EmbeddedLibrary> {
        self.libraries
            .get(name)
            .or_else(|| self.soname_index.get(name).and_then(|n| self.libraries.get(n)))
    }

    pub fn get_by_soname(&self, soname: &str) -> Option<&EmbeddedLibrary> {
        self.soname_index.get(soname).and_then(|name| self.libraries.get(name))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.libraries.contains_key(name) || self.soname_index.contains_key(name)
    }

    pub fn remove(&mut self, name: &str) -> Option<EmbeddedLibrary> {
        if let Some(lib) = self.libraries.remove(name) {
            if let Some(ref soname) = lib.soname {
                self.soname_index.remove(soname);
            }
            Some(lib)
        } else {
            None
        }
    }

    pub fn count(&self) -> usize {
        self.libraries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &EmbeddedLibrary)> {
        self.libraries.iter()
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.libraries.keys()
    }

    pub fn find_compatible(
        &self,
        name: &str,
        required_version: &LibraryVersion,
    ) -> Option<&EmbeddedLibrary> {
        self.get(name).filter(|lib| lib.version.is_compatible(required_version))
    }

    pub fn resolve_dependencies(
        &self,
        library: &EmbeddedLibrary,
    ) -> ElfResult<Vec<&EmbeddedLibrary>> {
        let mut resolved = Vec::new();
        let mut visited = Vec::new();

        self.resolve_deps_recursive(library, &mut resolved, &mut visited)?;

        Ok(resolved)
    }

    fn resolve_deps_recursive<'a>(
        &'a self,
        library: &'a EmbeddedLibrary,
        resolved: &mut Vec<&'a EmbeddedLibrary>,
        visited: &mut Vec<String>,
    ) -> ElfResult<()> {
        if visited.contains(&library.name) {
            return Err(ElfError::CircularDependency);
        }

        visited.push(library.name.clone());

        for dep_name in &library.dependencies {
            let dep = self.get(dep_name).ok_or(ElfError::LibraryNotFound)?;

            if !resolved.iter().any(|l| l.name == dep.name) {
                self.resolve_deps_recursive(dep, resolved, visited)?;
            }
        }

        if !resolved.iter().any(|l| l.name == library.name) {
            resolved.push(library);
        }

        visited.pop();
        Ok(())
    }

    pub fn total_size(&self) -> usize {
        self.libraries.values().map(|l| l.size()).sum()
    }

    pub fn clear(&mut self) {
        self.libraries.clear();
        self.soname_index.clear();
    }
}

impl Default for EmbeddedLibraryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

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

use crate::elf::loader::ElfImage;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::VirtAddr;

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

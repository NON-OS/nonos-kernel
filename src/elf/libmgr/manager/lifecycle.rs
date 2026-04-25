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
use super::types::LibraryState;
use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::fini::FiniArrayRunner;
use crate::elf::init::InitArrayRunner;

impl LibraryManager {
    pub fn relocate(&mut self, id: usize) -> ElfResult<()> {
        let library = self.libraries.get_mut(&id).ok_or(ElfError::LibraryNotFound)?;
        if library.state != LibraryState::Loading {
            return Ok(());
        }
        library.state = LibraryState::Relocating;
        if let Some(ref dynlink) = library.image.dynlink_info {
            if let (Some(symtab), Some(strtab)) = (dynlink.symtab, dynlink.strtab) {
                self.symbol_resolver.parse_symbols(
                    symtab,
                    strtab,
                    dynlink.strtab_size,
                    dynlink.sym_count,
                    library.image.base_addr,
                    id,
                )?;
            }
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
}

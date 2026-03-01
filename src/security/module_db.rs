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

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use core::ptr::{addr_of, addr_of_mut};

pub struct ModuleDB {
    trusted_modules: BTreeMap<String, [u8; 32]>,
}

static mut MODULE_DB: Option<ModuleDB> = None;

pub fn init() -> Result<(), &'static str> {
    // SAFETY: Called once during kernel initialization before any concurrent access
    unsafe {
        *addr_of_mut!(MODULE_DB) = Some(ModuleDB {
            trusted_modules: BTreeMap::new(),
        });
    }
    Ok(())
}

pub fn is_trusted_module(name: &str) -> bool {
    // SAFETY: Read-only access after initialization
    unsafe {
        if let Some(db) = (*addr_of!(MODULE_DB)).as_ref() {
            db.trusted_modules.contains_key(name)
        } else {
            false
        }
    }
}

pub fn get_loaded_modules() -> Vec<String> {
    // SAFETY: Read-only access after initialization
    unsafe {
        if let Some(db) = (*addr_of!(MODULE_DB)).as_ref() {
            db.trusted_modules.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

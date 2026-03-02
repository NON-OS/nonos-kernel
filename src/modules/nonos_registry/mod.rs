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

pub mod error;
pub mod operations;
pub mod types;

#[cfg(test)]
mod tests;

pub use error::{RegistryError, RegistryResult};

pub use types::RegistryEntry;

pub use operations::{
    clear_registry,
    get_registry_entry,
    is_module_registered,
    list_registered_modules,
    register_module,
    registered_module_count,
    secure_erase_registry_entry,
    secure_unregister_module,
    unregister_module,
};

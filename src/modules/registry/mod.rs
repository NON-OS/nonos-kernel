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

pub mod constants;
pub mod error;
pub mod manager;
pub mod types;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{RegistryError, RegistryResult};
pub use manager::{
    get_module_by_id, get_module_entry, get_module_info, get_module_params, is_module_active,
    list_modules, module_count, register_module, set_module_params, set_module_state,
    set_module_state_by_name, unregister_module, ACTIVE_MODULES,
};
pub use types::{ModuleInfo, ModuleState};

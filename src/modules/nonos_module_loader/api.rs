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

use alloc::vec::Vec;
use super::error::ModuleLoaderResult;
use super::types::{NonosModuleInfo, NonosModuleType};
use super::manager::NONOS_MODULE_LOADER;

pub fn load_module(
    name: &str,
    module_type: NonosModuleType,
    code: Vec<u8>,
    signature: &[u8; 64],
) -> ModuleLoaderResult<u64> {
    NONOS_MODULE_LOADER.load_module(name, module_type, code, signature)
}

pub fn unload_module(module_id: u64) -> ModuleLoaderResult<()> {
    NONOS_MODULE_LOADER.unload_module(module_id)
}

pub fn start_module(module_id: u64) -> ModuleLoaderResult<()> {
    NONOS_MODULE_LOADER.start_module(module_id)
}

pub fn stop_module(module_id: u64) -> ModuleLoaderResult<()> {
    NONOS_MODULE_LOADER.stop_module(module_id)
}

pub fn get_module_info(module_id: u64) -> ModuleLoaderResult<NonosModuleInfo> {
    NONOS_MODULE_LOADER.get_module_info(module_id)
}

pub fn list_loaded_modules() -> Vec<u64> {
    NONOS_MODULE_LOADER.list_modules()
}

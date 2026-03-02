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
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;
use super::constants::MAX_REGISTERED_MODULES;
use super::error::{RegistryError, RegistryResult};
use super::types::{ModuleInfo, ModuleState};

pub static ACTIVE_MODULES: RwLock<BTreeMap<String, ModuleInfo>> = RwLock::new(BTreeMap::new());
static NEXT_MODULE_ID: AtomicU64 = AtomicU64::new(1);

pub fn register_module(name: &str, entry_point: Option<usize>) -> RegistryResult<u64> {
    let mut registry = ACTIVE_MODULES.write();

    if registry.len() >= MAX_REGISTERED_MODULES {
        return Err(RegistryError::RegistryFull);
    }

    if registry.contains_key(name) {
        return Err(RegistryError::ModuleAlreadyExists);
    }

    let id = NEXT_MODULE_ID.fetch_add(1, Ordering::Relaxed);
    let mut info = ModuleInfo::new(id, String::from(name));
    info.entry_point = entry_point;
    info.state = ModuleState::Loaded;
    info.load_time = crate::time::timestamp_millis();

    registry.insert(String::from(name), info);
    Ok(id)
}

pub fn unregister_module(name: &str) -> RegistryResult<()> {
    let mut registry = ACTIVE_MODULES.write();

    let info = registry.get(name).ok_or(RegistryError::ModuleNotFound)?;

    if info.state.is_active() {
        return Err(RegistryError::ModuleRunning);
    }

    registry.remove(name);
    Ok(())
}

pub fn is_module_active(name: &str) -> bool {
    let registry = ACTIVE_MODULES.read();
    registry
        .get(name)
        .map(|info| info.state.is_active())
        .unwrap_or(false)
}

pub fn get_module_info(name: &str) -> RegistryResult<ModuleInfo> {
    let registry = ACTIVE_MODULES.read();
    registry
        .get(name)
        .cloned()
        .ok_or(RegistryError::ModuleNotFound)
}

pub fn get_module_by_id(id: u64) -> RegistryResult<ModuleInfo> {
    let registry = ACTIVE_MODULES.read();
    registry
        .values()
        .find(|info| info.id == id)
        .cloned()
        .ok_or(RegistryError::ModuleNotFound)
}

pub fn list_modules() -> Vec<String> {
    let registry = ACTIVE_MODULES.read();
    registry.keys().cloned().collect()
}

pub fn set_module_state_by_name(name: &str, state: ModuleState) -> RegistryResult<()> {
    let mut registry = ACTIVE_MODULES.write();
    let info = registry.get_mut(name).ok_or(RegistryError::ModuleNotFound)?;
    info.state = state;
    Ok(())
}

pub fn module_count() -> usize {
    let registry = ACTIVE_MODULES.read();
    registry.len()
}

pub fn set_module_state(module_id: u64, state: ModuleState) -> RegistryResult<()> {
    let mut registry = ACTIVE_MODULES.write();
    let info = registry
        .values_mut()
        .find(|info| info.id == module_id)
        .ok_or(RegistryError::ModuleNotFound)?;
    info.state = state;
    Ok(())
}

pub fn get_module_entry(module_id: u64) -> RegistryResult<u64> {
    let registry = ACTIVE_MODULES.read();
    registry
        .values()
        .find(|info| info.id == module_id)
        .and_then(|info| info.entry_point.map(|e| e as u64))
        .ok_or(RegistryError::ModuleNotFound)
}

pub fn set_module_params(module_id: u64, params: String) -> RegistryResult<()> {
    let mut registry = ACTIVE_MODULES.write();
    let info = registry
        .values_mut()
        .find(|info| info.id == module_id)
        .ok_or(RegistryError::ModuleNotFound)?;
    info.params = Some(params);
    Ok(())
}

pub fn get_module_params(module_id: u64) -> RegistryResult<Option<String>> {
    let registry = ACTIVE_MODULES.read();
    registry
        .values()
        .find(|info| info.id == module_id)
        .map(|info| info.params.clone())
        .ok_or(RegistryError::ModuleNotFound)
}

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


use alloc::{string::String, vec::Vec, collections::BTreeMap};
use spin::Mutex;
use core::ptr;
use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use super::types::RegistryEntry;
use super::error::{RegistryError, RegistryResult};

static MODULE_REGISTRY: Mutex<BTreeMap<String, RegistryEntry>> = Mutex::new(BTreeMap::new());

pub fn register_module(manifest: &ModuleManifest) -> RegistryResult<()> {
    match manifest.privacy_policy {
        PrivacyPolicy::ZeroStateOnly | PrivacyPolicy::Ephemeral => {}
        _ => return Err(RegistryError::InvalidPrivacyPolicy),
    }

    {
        let registry = MODULE_REGISTRY.lock();
        if registry.contains_key(&manifest.name) {
            return Err(RegistryError::AlreadyExists);
        }
    }

    let attested = manifest.verify_attestation();
    if !attested {
        return Err(RegistryError::AttestationFailed);
    }

    let entry = RegistryEntry::new(manifest.clone(), attested);

    MODULE_REGISTRY.lock().insert(manifest.name.clone(), entry);

    Ok(())
}

pub fn unregister_module(module_name: &str) -> RegistryResult<()> {
    let mut registry = MODULE_REGISTRY.lock();
    if registry.remove(module_name).is_some() {
        Ok(())
    } else {
        Err(RegistryError::NotFound)
    }
}

pub fn list_registered_modules() -> Vec<String> {
    MODULE_REGISTRY.lock().keys().cloned().collect()
}

pub fn get_registry_entry(module_name: &str) -> Option<RegistryEntry> {
    MODULE_REGISTRY.lock().get(module_name).cloned()
}

pub fn is_module_registered(module_name: &str) -> bool {
    MODULE_REGISTRY.lock().contains_key(module_name)
}

pub fn registered_module_count() -> usize {
    MODULE_REGISTRY.lock().len()
}

pub fn secure_erase_registry_entry(module_name: &str) -> RegistryResult<()> {
    let mut registry = MODULE_REGISTRY.lock();
    let entry = registry
        .get_mut(module_name)
        .ok_or(RegistryError::NotFound)?;

    entry.manifest.secure_erase();

    for b in entry.hash.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();

    entry.attested = false;

    Ok(())
}

pub fn secure_unregister_module(module_name: &str) -> RegistryResult<()> {
    secure_erase_registry_entry(module_name)?;
    unregister_module(module_name)
}

pub fn clear_registry() {
    let mut registry = MODULE_REGISTRY.lock();

    for entry in registry.values_mut() {
        entry.manifest.secure_erase();
        for b in entry.hash.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
    }

    compiler_fence();
    memory_fence();

    registry.clear();
}

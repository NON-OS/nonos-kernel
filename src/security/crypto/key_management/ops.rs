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
use core::sync::atomic::Ordering;
use super::types::{KeyType, KeyUsage};
use super::entry::KeyEntry;
use super::store::{KEY_STORE, KEY_STORE_INITIALIZED};
use super::audit::KeyOperation;
use super::errors::{KeyError, KeyResult};

pub fn generate_key(
    name: String,
    key_type: KeyType,
    usage: KeyUsage,
    owner: u64,
) -> KeyResult<u64> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    let key_len = key_type.key_length();
    let mut material = alloc::vec![0u8; key_len];
    crate::crypto::rng::fill_bytes(&mut material);

    if material.iter().all(|&b| b == 0) {
        return Err(KeyError::CryptoError);
    }

    let mut store = KEY_STORE.write();
    let id = store.next_id;
    store.next_id += 1;

    let entry = KeyEntry::new(id, name.clone(), key_type, material, usage, owner);
    let fingerprint = entry.fingerprint;
    store.keys.insert(id, entry);
    store.log_operation(KeyOperation::Create, id, fingerprint, owner, true);

    crate::log::info!("[KEY_MGMT] Generated key {} (ID: {})", name, id);
    Ok(id)
}

pub fn import_key(
    name: String,
    key_type: KeyType,
    material: Vec<u8>,
    usage: KeyUsage,
    owner: u64,
) -> KeyResult<u64> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    if material.len() != key_type.key_length() {
        return Err(KeyError::InvalidKeyLength);
    }

    let mut store = KEY_STORE.write();
    let id = store.next_id;
    store.next_id += 1;

    let entry = KeyEntry::new(id, name.clone(), key_type, material, usage, owner);
    let fingerprint = entry.fingerprint;
    store.keys.insert(id, entry);
    store.log_operation(KeyOperation::Import, id, fingerprint, owner, true);

    crate::log::info!("[KEY_MGMT] Imported key {} (ID: {})", name, id);
    Ok(id)
}

pub fn use_key(key_id: u64, caller: u64) -> KeyResult<Vec<u8>> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    let mut store = KEY_STORE.write();
    let entry = store.keys.get_mut(&key_id).ok_or(KeyError::KeyNotFound)?;
    let fingerprint = entry.fingerprint;

    if !entry.active {
        store.log_operation(KeyOperation::Use, key_id, fingerprint, caller, false);
        return Err(KeyError::KeyInactive);
    }

    if entry.expires_at != 0 && crate::time::timestamp_secs() > entry.expires_at {
        store.log_operation(KeyOperation::Use, key_id, fingerprint, caller, false);
        return Err(KeyError::KeyExpired);
    }

    if entry.owner_module != caller && caller != 0 {
        store.log_operation(KeyOperation::Use, key_id, fingerprint, caller, false);
        return Err(KeyError::PermissionDenied);
    }

    entry.touch();
    let material = entry.material().to_vec();
    store.log_operation(KeyOperation::Use, key_id, fingerprint, caller, true);

    Ok(material)
}

pub fn export_key(key_id: u64, caller: u64) -> KeyResult<Vec<u8>> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    let mut store = KEY_STORE.write();
    let entry = store.keys.get(&key_id).ok_or(KeyError::KeyNotFound)?;

    let fingerprint = entry.fingerprint;
    let exportable = entry.usage.exportable;
    let owner = entry.owner_module;
    let material = entry.material().to_vec();

    if !exportable {
        store.log_operation(KeyOperation::Export, key_id, fingerprint, caller, false);
        return Err(KeyError::ExportNotAllowed);
    }

    if owner != caller && caller != 0 {
        store.log_operation(KeyOperation::Export, key_id, fingerprint, caller, false);
        return Err(KeyError::PermissionDenied);
    }

    store.log_operation(KeyOperation::Export, key_id, fingerprint, caller, true);
    Ok(material)
}

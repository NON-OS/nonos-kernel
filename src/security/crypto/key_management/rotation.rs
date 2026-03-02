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

use core::sync::atomic::Ordering;
use super::entry::KeyEntry;
use super::store::{KEY_STORE, KEY_STORE_INITIALIZED};
use super::audit::KeyOperation;
use super::errors::{KeyError, KeyResult};

pub fn rotate_key(old_key_id: u64, caller: u64) -> KeyResult<u64> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    let mut store = KEY_STORE.write();
    let old_entry = store.keys.get(&old_key_id).ok_or(KeyError::KeyNotFound)?;

    if old_entry.owner_module != caller && caller != 0 {
        return Err(KeyError::PermissionDenied);
    }

    let key_type = old_entry.key_type;
    let usage = old_entry.usage;
    let name = old_entry.name.clone();
    let owner = old_entry.owner_module;
    let old_rotation_count = old_entry.rotation_count;
    let old_fingerprint = old_entry.fingerprint;

    let key_len = key_type.key_length();
    let mut material = alloc::vec![0u8; key_len];
    crate::crypto::rng::fill_bytes(&mut material);

    let new_id = store.next_id;
    store.next_id += 1;

    let mut new_entry = KeyEntry::new(new_id, name.clone(), key_type, material, usage, owner);
    new_entry.rotation_count = old_rotation_count + 1;
    new_entry.previous_key_id = Some(old_key_id);
    let new_fingerprint = new_entry.fingerprint;

    if let Some(old) = store.keys.get_mut(&old_key_id) {
        old.active = false;
    }

    store.keys.insert(new_id, new_entry);
    store.log_operation(KeyOperation::Rotate, old_key_id, old_fingerprint, caller, true);
    store.log_operation(KeyOperation::Create, new_id, new_fingerprint, caller, true);

    crate::log::info!(
        "[KEY_MGMT] Rotated key {} -> {} (rotation #{})",
        old_key_id, new_id, old_rotation_count + 1
    );

    Ok(new_id)
}

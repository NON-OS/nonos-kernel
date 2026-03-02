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


use core::sync::atomic::Ordering;
use super::store::{KEY_STORE, KEY_STORE_INITIALIZED};
use super::audit::KeyOperation;
use super::errors::{KeyError, KeyResult};

pub fn delete_key(key_id: u64, caller: u64) -> KeyResult<()> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    let mut store = KEY_STORE.write();

    {
        let entry = store.keys.get(&key_id).ok_or(KeyError::KeyNotFound)?;
        let fingerprint = entry.fingerprint;
        let owner = entry.owner_module;

        if owner != caller && caller != 0 {
            store.log_operation(KeyOperation::Delete, key_id, fingerprint, caller, false);
            return Err(KeyError::PermissionDenied);
        }
    }

    if let Some(entry) = store.keys.get_mut(&key_id) {
        let fingerprint = entry.fingerprint;
        entry.secure_clear();
        store.keys.remove(&key_id);
        store.log_operation(KeyOperation::Delete, key_id, fingerprint, caller, true);
    }

    crate::log::info!("[KEY_MGMT] Deleted key {}", key_id);
    Ok(())
}

pub fn delete_all_keys() {
    let mut store = KEY_STORE.write();
    store.clear_all();
    crate::log::info!("[KEY_MGMT] All keys securely deleted");
}

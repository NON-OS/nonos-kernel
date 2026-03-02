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

pub fn derive_key(
    name: String,
    key_type: KeyType,
    usage: KeyUsage,
    context: &[u8],
    owner: u64,
) -> KeyResult<u64> {
    if !KEY_STORE_INITIALIZED.load(Ordering::SeqCst) {
        return Err(KeyError::NotInitialized);
    }

    let mut store = KEY_STORE.write();
    let master = store.master_key.ok_or(KeyError::NoMasterKey)?;

    let key_len = key_type.key_length();
    let mut derived = alloc::vec![0u8; key_len];

    let mut prev_block = Vec::new();
    let mut offset = 0;

    for i in 1u8.. {
        if offset >= key_len {
            break;
        }

        let mut input = prev_block.clone();
        input.extend_from_slice(context);
        input.push(i);

        let block = crate::crypto::hmac::hmac_sha256(&master, &input);
        prev_block = block.to_vec();

        let copy_len = (key_len - offset).min(32);
        derived[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
        offset += copy_len;
    }

    let id = store.next_id;
    store.next_id += 1;

    let entry = KeyEntry::new(id, name.clone(), key_type, derived, usage, owner);
    let fingerprint = entry.fingerprint;
    store.keys.insert(id, entry);
    store.log_operation(KeyOperation::Derive, id, fingerprint, owner, true);

    crate::log::info!("[KEY_MGMT] Derived key {} (ID: {})", name, id);
    Ok(id)
}

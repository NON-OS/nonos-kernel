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

use super::audit::KeyOperation;
use super::entry::KeyEntry;
use super::errors::{KeyError, KeyResult};
use super::store::{KEY_STORE, KEY_STORE_INITIALIZED};
use super::types::{KeyType, KeyUsage};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let effective_salt = if salt.is_empty() { &[0u8; 32] } else { salt };
    crate::crypto::hmac::hmac_sha256(effective_salt, ikm)
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 32;
    let n = (length + hash_len - 1) / hash_len;
    if n > 255 {
        return Vec::new();
    }
    let mut okm = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new();
    for i in 1..=n {
        let mut input = t_prev.clone();
        input.extend_from_slice(info);
        input.push(i as u8);
        let t = crate::crypto::hmac::hmac_sha256(prk, &input);
        t_prev = t.to_vec();
        okm.extend_from_slice(&t);
    }
    okm.truncate(length);
    okm
}

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

pub fn derive_subkey(master: &[u8], context: &str, key_id: u64, length: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"NONOS-SUBKEY-V1:");
    info.extend_from_slice(context.as_bytes());
    info.push(0);
    info.extend_from_slice(&key_id.to_le_bytes());
    hkdf(&[], master, &info, length)
}

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

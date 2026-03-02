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
use super::types::{KeyType, KeyUsage};
use super::store::KEY_STORE;
use super::errors::{KeyError, KeyResult};
use crate::crypto::constant_time::ct_eq_32;

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub id: u64,
    pub name: String,
    pub key_type: KeyType,
    pub fingerprint: [u8; 32],
    pub usage: KeyUsage,
    pub created_at: u64,
    pub last_used: u64,
    pub expires_at: u64,
    pub rotation_count: u32,
    pub active: bool,
}

pub fn get_key_info(key_id: u64) -> KeyResult<KeyInfo> {
    let store = KEY_STORE.read();
    let entry = store.keys.get(&key_id).ok_or(KeyError::KeyNotFound)?;

    Ok(KeyInfo {
        id: entry.id,
        name: entry.name.clone(),
        key_type: entry.key_type,
        fingerprint: entry.fingerprint,
        usage: entry.usage,
        created_at: entry.created_at,
        last_used: entry.last_used,
        expires_at: entry.expires_at,
        rotation_count: entry.rotation_count,
        active: entry.active,
    })
}

pub fn list_keys() -> Vec<u64> {
    let store = KEY_STORE.read();
    store.keys.keys().copied().collect()
}

pub fn list_keys_by_owner(owner: u64) -> Vec<u64> {
    let store = KEY_STORE.read();
    store.keys.iter()
        .filter(|(_, e)| e.owner_module == owner)
        .map(|(id, _)| *id)
        .collect()
}

pub fn find_key_by_fingerprint(fingerprint: &[u8; 32]) -> Option<u64> {
    let store = KEY_STORE.read();
    for (id, entry) in &store.keys {
        if ct_eq_32(&entry.fingerprint, fingerprint) {
            return Some(*id);
        }
    }
    None
}

pub fn key_count() -> usize {
    KEY_STORE.read().keys.len()
}

pub fn active_key_count() -> usize {
    let store = KEY_STORE.read();
    store.keys.values().filter(|e| e.active).count()
}

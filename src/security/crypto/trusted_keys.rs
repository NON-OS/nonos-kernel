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

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub struct TrustedKeyDB {
    pub keys: BTreeMap<String, Vec<u8>>,
    pub last_update: AtomicU64,
}

static TRUSTED_KEY_DB: Mutex<Option<TrustedKeyDB>> = Mutex::new(None);

pub fn init() -> Result<(), &'static str> {
    let db = TrustedKeyDB {
        keys: BTreeMap::new(),
        last_update: AtomicU64::new(crate::time::timestamp_millis()),
    };
    let mut lock = TRUSTED_KEY_DB.lock();
    *lock = Some(db);
    Ok(())
}

pub fn add_trusted_key(name: &str, key: &[u8]) {
    let mut lock = TRUSTED_KEY_DB.lock();
    if let Some(db) = lock.as_mut() {
        db.keys.insert(name.into(), key.to_vec());
        db.last_update.store(crate::time::timestamp_millis(), Ordering::Relaxed);
    }
}

pub fn get_trusted_key(name: &str) -> Option<Vec<u8>> {
    let lock = TRUSTED_KEY_DB.lock();
    lock.as_ref()?.keys.get(name).cloned()
}

pub fn verify_signature(name: &str, message: &[u8], signature: &[u8]) -> bool {
    let key = get_trusted_key(name);
    match key {
        Some(public_key) => crate::crypto::verify_signature(&public_key, message, signature),
        None => false,
    }
}

pub fn list_trusted_keys() -> Vec<(String, Vec<u8>)> {
    let lock = TRUSTED_KEY_DB.lock();
    if let Some(db) = lock.as_ref() {
        db.keys.iter().map(|(n, k)| (n.clone(), k.clone())).collect()
    } else {
        Vec::new()
    }
}

const NONOS_ROOT_PUBKEY: [u8; 32] = [
    0x8a, 0x7c, 0x2b, 0x9f, 0x4d, 0xe1, 0x3a, 0x56,
    0xc8, 0x91, 0x0e, 0xf7, 0x62, 0xd4, 0xb5, 0x1c,
    0xa3, 0x78, 0x5e, 0x20, 0x9b, 0xf6, 0x4c, 0x83,
    0x17, 0xe9, 0x6a, 0xd0, 0x35, 0xbc, 0x42, 0x1f,
];

const NONOS_MODULES_PUBKEY: [u8; 32] = [
    0x3d, 0x52, 0xa7, 0xe8, 0x14, 0xc9, 0x6b, 0xf0,
    0x81, 0x2e, 0x5f, 0x93, 0xd6, 0x47, 0xba, 0x0c,
    0x75, 0xe3, 0x28, 0x9a, 0xf1, 0x4d, 0xc6, 0x82,
    0x5b, 0xa0, 0x37, 0xec, 0x19, 0x64, 0xdf, 0x8e,
];

const NONOS_PACKAGES_PUBKEY: [u8; 32] = [
    0x71, 0xc4, 0x36, 0x8d, 0xe2, 0x5b, 0xa9, 0x0f,
    0x43, 0x97, 0xde, 0x6a, 0x15, 0xb8, 0xc2, 0x74,
    0x9e, 0x50, 0x2d, 0xf3, 0x86, 0xac, 0x1b, 0x67,
    0xe4, 0x39, 0xd5, 0x08, 0x7c, 0xf2, 0xab, 0x61,
];

const NONOS_UPDATES_PUBKEY: [u8; 32] = [
    0xb2, 0x68, 0x1e, 0xf5, 0xa3, 0x7d, 0xc0, 0x49,
    0x96, 0x2f, 0x84, 0xdb, 0x51, 0x0a, 0xe7, 0x3c,
    0x6e, 0xb9, 0x24, 0xf8, 0x45, 0xd1, 0x7a, 0xc3,
    0x92, 0x5d, 0x06, 0xef, 0x38, 0xad, 0x70, 0x1b,
];

const NONOS_WALLET_PUBKEY: [u8; 32] = [
    0x59, 0xa4, 0xed, 0x32, 0x87, 0xcf, 0x16, 0x7b,
    0xe0, 0x4a, 0xb3, 0x95, 0xd8, 0x23, 0x6c, 0xf1,
    0xae, 0x54, 0xc7, 0x09, 0x62, 0xdb, 0x3f, 0x8e,
    0x1a, 0x76, 0xc5, 0x40, 0xbd, 0x98, 0x2e, 0x53,
];

pub fn init_trusted_keys() {
    if let Err(e) = init() {
        crate::log::log_warn!("Trusted keys init returned error (may be already initialized): {}", e);
    }

    add_trusted_key("nonos.root", &NONOS_ROOT_PUBKEY);
    add_trusted_key("nonos.modules", &NONOS_MODULES_PUBKEY);
    add_trusted_key("nonos.packages", &NONOS_PACKAGES_PUBKEY);
    add_trusted_key("nonos.updates", &NONOS_UPDATES_PUBKEY);
    add_trusted_key("nonos.wallet", &NONOS_WALLET_PUBKEY);

    crate::log::info!("Trusted keys initialized with {} built-in keys", list_trusted_keys().len());
}

pub fn get_trusted_keys() -> Vec<TrustedKey> {
    let keys = list_trusted_keys();
    keys.into_iter().map(|(name, key)| TrustedKey { name, key }).collect()
}

#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub struct TrustedKey {
    pub name: String,
    pub key: Vec<u8>,
}

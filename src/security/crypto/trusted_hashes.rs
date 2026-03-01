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

pub struct TrustedHashDB {
    hashes: BTreeMap<String, [u8; 32]>,
    last_update: AtomicU64,
}

static TRUSTED_HASH_DB: Mutex<Option<TrustedHashDB>> = Mutex::new(None);

pub fn init() -> Result<(), &'static str> {
    let db = TrustedHashDB {
        hashes: BTreeMap::new(),
        last_update: AtomicU64::new(crate::time::timestamp_millis()),
    };
    let mut lock = TRUSTED_HASH_DB.lock();
    *lock = Some(db);
    Ok(())
}

pub fn add_trusted_hash(name: &str, hash: [u8; 32]) {
    let mut lock = TRUSTED_HASH_DB.lock();
    if let Some(db) = lock.as_mut() {
        db.hashes.insert(name.into(), hash);
        db.last_update.store(crate::time::timestamp_millis(), Ordering::Relaxed);
    }
}

pub fn get_trusted_hash(name: &str) -> Option<[u8; 32]> {
    let lock = TRUSTED_HASH_DB.lock();
    lock.as_ref()?.hashes.get(name).cloned()
}

pub fn verify_integrity(name: &str, actual_hash: &[u8; 32]) -> bool {
    let lock = TRUSTED_HASH_DB.lock();
    lock.as_ref()
        .map(|db| db.hashes.get(name).map_or(false, |trusted| trusted == actual_hash))
        .unwrap_or(false)
}

pub fn list_trusted_hashes() -> Vec<(String, [u8; 32])> {
    let lock = TRUSTED_HASH_DB.lock();
    if let Some(db) = lock.as_ref() {
        db.hashes.iter().map(|(n, h)| (n.clone(), *h)).collect()
    } else {
        Vec::new()
    }
}

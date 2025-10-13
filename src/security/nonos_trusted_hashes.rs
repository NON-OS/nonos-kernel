#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Trusted hashes for system files
pub struct NonosTrustedHashDB {
    hashes: BTreeMap<String, [u8; 32]>,
    last_update: AtomicU64,
}

static TRUSTED_HASH_DB: Mutex<Option<NonosTrustedHashDB>> = Mutex::new(None);

/// Initialize trusted hashes database
pub fn init() -> Result<(), &'static str> {
    let db = NonosTrustedHashDB {
        hashes: BTreeMap::new(),
        last_update: AtomicU64::new(crate::time::timestamp_millis()),
    };
    let mut lock = TRUSTED_HASH_DB.lock();
    *lock = Some(db);
    Ok(())
}

/// Add or update trusted hash for a system object
pub fn add_trusted_hash(name: &str, hash: [u8; 32]) {
    let mut lock = TRUSTED_HASH_DB.lock();
    if let Some(db) = lock.as_mut() {
        db.hashes.insert(name.into(), hash);
        db.last_update.store(crate::time::timestamp_millis(), Ordering::Relaxed);
    }
}

/// Get trusted hash for a system object
pub fn get_trusted_hash(name: &str) -> Option<[u8; 32]> {
    let lock = TRUSTED_HASH_DB.lock();
    lock.as_ref()?.hashes.get(name).cloned()
}

/// Verify integrity of a named object against its trusted hash
pub fn verify_integrity(name: &str, actual_hash: &[u8; 32]) -> bool {
    let lock = TRUSTED_HASH_DB.lock();
    lock.as_ref()
        .map(|db| db.hashes.get(name).map_or(false, |trusted| trusted == actual_hash))
        .unwrap_or(false)
}

/// List all trusted hashes
pub fn list_trusted_hashes() -> Vec<(String, [u8; 32])> {
    let lock = TRUSTED_HASH_DB.lock();
    if let Some(db) = lock.as_ref() {
        db.hashes.iter().map(|(n, h)| (n.clone(), *h)).collect()
    } else {
        Vec::new()
    }
}

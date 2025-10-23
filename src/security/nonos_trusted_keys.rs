#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Trusted public keys
pub struct NonosTrustedKeyDB {
    pub keys: BTreeMap<String, Vec<u8>>, // name/id -> key bytes
    pub last_update: AtomicU64,
}

static TRUSTED_KEY_DB: Mutex<Option<NonosTrustedKeyDB>> = Mutex::new(None);

/// Initialize trusted keys database
pub fn init() -> Result<(), &'static str> {
    let db = NonosTrustedKeyDB {
        keys: BTreeMap::new(),
        last_update: AtomicU64::new(crate::time::timestamp_millis()),
    };
    let mut lock = TRUSTED_KEY_DB.lock();
    *lock = Some(db);
    Ok(())
}

/// Add or update a trusted key
pub fn add_trusted_key(name: &str, key: &[u8]) {
    let mut lock = TRUSTED_KEY_DB.lock();
    if let Some(db) = lock.as_mut() {
        db.keys.insert(name.into(), key.to_vec());
        db.last_update.store(crate::time::timestamp_millis(), Ordering::Relaxed);
    }
}

/// Retrieve a trusted key
pub fn get_trusted_key(name: &str) -> Option<Vec<u8>> {
    let lock = TRUSTED_KEY_DB.lock();
    lock.as_ref()?.keys.get(name).cloned()
}

/// Verify a signature against a trusted key
pub fn verify_signature(name: &str, message: &[u8], signature: &[u8]) -> bool {
    let key = get_trusted_key(name);
    match key {
        Some(public_key) => crate::crypto::verify_signature(&public_key, message, signature),
        None => false,
    }
}

/// List all trusted keys
pub fn list_trusted_keys() -> Vec<(String, Vec<u8>)> {
    let lock = TRUSTED_KEY_DB.lock();
    if let Some(db) = lock.as_ref() {
        db.keys.iter().map(|(n, k)| (n.clone(), k.clone())).collect()
    } else {
        Vec::new()
    }
}

/// Initialize trusted key store
pub fn init_trusted_keys() {
    // Initialize the trusted key registry
}

/// Compatibility alias
pub fn get_trusted_keys() -> Vec<TrustedKey> {
    let keys = list_trusted_keys();
    keys.into_iter().map(|(name, key)| TrustedKey { name, key }).collect()
}

/// Trusted key struct for compatibility
#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub struct TrustedKey {
    pub name: String,
    pub key: Vec<u8>,
}

// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::log::logger::{log_error, log_info, log_warn};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

include!(concat!(env!("OUT_DIR"), "/keys_generated.rs"));

pub const PK_LEN: usize = 32;
pub const MAX_KEYS: usize = 16;
pub const MAX_REVOKED: usize = 32;
pub type KeyId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Valid,
    Revoked,
    Unknown,
    VersionTooOld,
    Expired,
}

#[derive(Clone, Copy)]
pub struct RevocationEntry {
    pub key_id: KeyId,
    pub revoked_at: u64,
    pub reason: RevocationReason,
}

impl RevocationEntry {
    pub const fn empty() -> Self {
        Self {
            key_id: [0u8; 32],
            revoked_at: 0,
            reason: RevocationReason::Unspecified,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromised = 1,
    KeySuperseded = 2,
    AffiliationChanged = 3,
    CessationOfOperation = 4,
}

pub struct KeyStore {
    pub keys: [[u8; 32]; MAX_KEYS],
    pub versions: [u32; MAX_KEYS],
    pub count: usize,
    pub revoked: [RevocationEntry; MAX_REVOKED],
    pub revoked_count: usize,
    pub minimum_version: u32,
}

impl KeyStore {
    pub const fn new() -> Self {
        Self {
            keys: [[0u8; 32]; MAX_KEYS],
            versions: [0u32; MAX_KEYS],
            count: 0,
            revoked: [RevocationEntry::empty(); MAX_REVOKED],
            revoked_count: 0,
            minimum_version: 1,
        }
    }

    pub fn is_revoked(&self, key_id: &KeyId) -> bool {
        for i in 0..self.revoked_count {
            if constant_time_eq(&self.revoked[i].key_id, key_id) {
                return true;
            }
        }
        false
    }

    pub fn revoke_key(&mut self, key_id: KeyId, reason: RevocationReason, timestamp: u64) -> bool {
        if self.revoked_count >= MAX_REVOKED {
            return false;
        }
        if self.is_revoked(&key_id) {
            return true;
        }
        self.revoked[self.revoked_count] = RevocationEntry {
            key_id,
            revoked_at: timestamp,
            reason,
        };
        self.revoked_count += 1;
        true
    }

    pub fn validate_key(&self, pubkey: &[u8; PK_LEN], version: u32) -> KeyStatus {
        let key_id = derive_keyid(pubkey);
        if self.is_revoked(&key_id) {
            return KeyStatus::Revoked;
        }
        if version < self.minimum_version {
            return KeyStatus::VersionTooOld;
        }
        for i in 0..self.count {
            if constant_time_eq(&self.keys[i], pubkey) {
                return KeyStatus::Valid;
            }
        }
        KeyStatus::Unknown
    }
}

pub static KEYSTORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
static INIT_DONE: AtomicBool = AtomicBool::new(false);
static CURRENT_VERSION: AtomicU32 = AtomicU32::new(KEY_VERSION);

pub fn derive_keyid(pubkey: &[u8; PK_LEN]) -> KeyId {
    let mut h = blake3::Hasher::new_derive_key("NONOS:KEYID:ED25519:v1");
    h.update(pubkey);
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out.as_bytes()[0..32]);
    id
}

#[inline(never)]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn add_key_versioned(pubkey: &[u8; PK_LEN], version: u32) -> Result<KeyId, &'static str> {
    let id = derive_keyid(pubkey);
    let mut store = KEYSTORE.lock();

    if store.is_revoked(&id) {
        return Err("key revoked");
    }
    if version < store.minimum_version {
        return Err("version too old");
    }

    for i in 0..store.count {
        if constant_time_eq(&store.keys[i], pubkey) {
            if version > store.versions[i] {
                store.versions[i] = version;
            }
            return Ok(id);
        }
    }

    if store.count >= MAX_KEYS {
        return Err("keystore full");
    }

    let idx = store.count;
    store.keys[idx] = *pubkey;
    store.versions[idx] = version;
    store.count += 1;
    INIT_DONE.store(true, Ordering::SeqCst);
    Ok(id)
}

pub fn add_key(pubkey: &[u8; PK_LEN]) -> Result<KeyId, &'static str> {
    add_key_versioned(pubkey, CURRENT_VERSION.load(Ordering::SeqCst))
}

pub fn init_nonos_keys() -> Result<usize, &'static str> {
    if INIT_DONE.load(Ordering::SeqCst) {
        log_warn("crypto", "keystore already initialized");
        let store = KEYSTORE.lock();
        return Ok(store.count);
    }

    log_info("crypto", "initializing NONOS keystore");

    let mut is_zero = true;
    for byte in NONOS_PUBLIC_KEY.iter() {
        if *byte != 0 {
            is_zero = false;
            break;
        }
    }

    if is_zero {
        log_error("crypto", "CRITICAL: signing key is zero");
        return Err("invalid signing key");
    }

    match add_key_versioned(&NONOS_PUBLIC_KEY, KEY_VERSION) {
        Ok(id) => {
            if !constant_time_eq(&id, &NONOS_KEY_ID) {
                log_error("crypto", "key ID mismatch");
                return Err("key verification failed");
            }
            log_info("crypto", "NONOS signing key loaded");
        }
        Err(e) => {
            log_error("crypto", "failed to load signing key");
            return Err(e);
        }
    }

    log_info("crypto", "keystore ready");
    Ok(1)
}

pub fn is_initialized() -> bool {
    INIT_DONE.load(Ordering::SeqCst)
}

pub fn key_count() -> usize {
    let store = KEYSTORE.lock();
    store.count
}

pub fn get_minimum_version() -> u32 {
    let store = KEYSTORE.lock();
    store.minimum_version
}

pub fn set_minimum_version(version: u32) -> bool {
    let mut store = KEYSTORE.lock();
    if version > store.minimum_version {
        store.minimum_version = version;
        log_info("crypto", "minimum version updated");
        true
    } else {
        false
    }
}

pub fn revoke_key_by_pubkey(
    pubkey: &[u8; PK_LEN],
    reason: RevocationReason,
    timestamp: u64,
) -> bool {
    let key_id = derive_keyid(pubkey);
    let mut store = KEYSTORE.lock();
    if store.revoke_key(key_id, reason, timestamp) {
        log_warn("crypto", "key revoked");
        true
    } else {
        log_error("crypto", "revocation failed");
        false
    }
}

pub fn validate_key(pubkey: &[u8; PK_LEN], version: u32) -> KeyStatus {
    let store = KEYSTORE.lock();
    store.validate_key(pubkey, version)
}

pub fn get_nonos_key() -> &'static [u8; 32] {
    &NONOS_PUBLIC_KEY
}

pub fn get_nonos_key_id() -> &'static [u8; 32] {
    &NONOS_KEY_ID
}

pub fn get_key_fingerprint() -> &'static str {
    KEY_FINGERPRINT
}

pub fn get_build_timestamp() -> u64 {
    BUILD_TIMESTAMP
}

pub const NONOS_SIGNING_KEY: &[u8; 32] = &NONOS_PUBLIC_KEY;

pub use init_nonos_keys as init_production_keys;

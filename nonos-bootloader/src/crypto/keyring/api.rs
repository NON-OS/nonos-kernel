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

/*
 * Key management public API.
 */

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::log::logger::{log_error, log_info, log_warn};

use super::store::KeyStore;
use super::types::{KeyId, KeyStatus, RevocationReason, PK_LEN};
use super::util::{constant_time_eq, is_zero_key};

include!(concat!(env!("OUT_DIR"), "/keys_generated.rs"));

pub static KEYSTORE: Mutex<KeyStore> = Mutex::new(KeyStore::new());
static INIT_DONE: AtomicBool = AtomicBool::new(false);
static CURRENT_VERSION: AtomicU32 = AtomicU32::new(KEY_VERSION);

pub fn add_key_versioned(pubkey: &[u8; PK_LEN], version: u32) -> Result<KeyId, &'static str> {
    let mut store = KEYSTORE.lock();
    let result = store.add_key(pubkey, version);
    if result.is_ok() {
        INIT_DONE.store(true, Ordering::SeqCst);
    }
    result
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

    if is_zero_key(&NONOS_PUBLIC_KEY) {
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

pub fn revoke_key_by_pubkey(pubkey: &[u8; PK_LEN], reason: RevocationReason, timestamp: u64) -> bool {
    use super::util::derive_keyid;
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

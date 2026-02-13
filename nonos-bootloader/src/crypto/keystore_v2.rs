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

use super::keys::{derive_keyid, KeyId, PK_LEN};
use spin::Mutex;

pub const MAX_TRUSTED_KEYS: usize = 8;
pub const DS_KEY_ROTATION: &str = "NONOS:KEY:ROTATION:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Primary = 0x01,
    Secondary = 0x02,
    Emergency = 0x03,
    PreAuthorized = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyValidationResult {
    Valid,
    NotYetValid,
    Expired,
    Revoked,
    VersionTooOld,
    NotFound,
    RequiresCoSignature,
}

#[derive(Clone, Copy)]
pub struct TrustedKey {
    pub key_id: KeyId,
    pub public_key: [u8; PK_LEN],
    pub version: u32,
    pub added_at: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub key_type: KeyType,
    pub active: bool,
}

impl TrustedKey {
    pub const fn empty() -> Self {
        Self {
            key_id: [0u8; 32],
            public_key: [0u8; 32],
            version: 0,
            added_at: 0,
            valid_from: 0,
            valid_until: 0,
            key_type: KeyType::Primary,
            active: false,
        }
    }

    pub fn new(
        public_key: [u8; PK_LEN],
        version: u32,
        valid_from: u64,
        valid_until: u64,
        key_type: KeyType,
    ) -> Self {
        let key_id = derive_keyid(&public_key);
        let added_at = 0;
        Self {
            key_id,
            public_key,
            version,
            added_at,
            valid_from,
            valid_until,
            key_type,
            active: true,
        }
    }

    pub fn is_valid_at(&self, timestamp: u64, minimum_version: u32) -> KeyValidationResult {
        if !self.active {
            return KeyValidationResult::Revoked;
        }
        if timestamp < self.valid_from {
            return KeyValidationResult::NotYetValid;
        }
        if self.valid_until > 0 && timestamp > self.valid_until {
            return KeyValidationResult::Expired;
        }
        if self.version < minimum_version {
            return KeyValidationResult::VersionTooOld;
        }
        KeyValidationResult::Valid
    }
}

pub struct KeystoreV2 {
    keys: [TrustedKey; MAX_TRUSTED_KEYS],
    key_count: usize,
    minimum_version: u32,
    revocations: [[u8; 32]; 16],
    revocation_count: usize,
    require_cosign: bool,
}

impl KeystoreV2 {
    pub const fn new() -> Self {
        Self {
            keys: [TrustedKey::empty(); MAX_TRUSTED_KEYS],
            key_count: 0,
            minimum_version: 1,
            revocations: [[0u8; 32]; 16],
            revocation_count: 0,
            require_cosign: false,
        }
    }

    pub fn add_key(&mut self, key: TrustedKey) -> Result<(), &'static str> {
        if self.key_count >= MAX_TRUSTED_KEYS {
            return Err("keystore full");
        }
        if self.is_revoked(&key.key_id) {
            return Err("key is revoked");
        }
        for i in 0..self.key_count {
            if constant_time_eq(&self.keys[i].key_id, &key.key_id) {
                return Err("key already exists");
            }
        }
        self.keys[self.key_count] = key;
        self.key_count += 1;
        Ok(())
    }

    pub fn revoke_key(&mut self, key_id: &KeyId) -> bool {
        if self.revocation_count >= 16 {
            return false;
        }

        for i in 0..self.key_count {
            if constant_time_eq(&self.keys[i].key_id, key_id) {
                self.keys[i].active = false;
            }
        }

        self.revocations[self.revocation_count] = *key_id;
        self.revocation_count += 1;
        true
    }

    pub fn is_revoked(&self, key_id: &KeyId) -> bool {
        for i in 0..self.revocation_count {
            if constant_time_eq(&self.revocations[i], key_id) {
                return true;
            }
        }
        false
    }

    pub fn set_minimum_version(&mut self, version: u32) {
        if version > self.minimum_version {
            self.minimum_version = version;
        }
    }

    pub fn find_key(&self, key_id: &KeyId) -> Option<&TrustedKey> {
        for i in 0..self.key_count {
            if constant_time_eq(&self.keys[i].key_id, key_id) {
                return Some(&self.keys[i]);
            }
        }
        None
    }

    pub fn find_key_by_pubkey(&self, pubkey: &[u8; PK_LEN]) -> Option<&TrustedKey> {
        for i in 0..self.key_count {
            if constant_time_eq(&self.keys[i].public_key, pubkey) {
                return Some(&self.keys[i]);
            }
        }
        None
    }

    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8; 64],
        timestamp: u64,
    ) -> Result<KeyId, KeyValidationResult> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig = Signature::from_bytes(signature);

        for i in 0..self.key_count {
            let key = &self.keys[i];

            let validation = key.is_valid_at(timestamp, self.minimum_version);
            if validation != KeyValidationResult::Valid {
                continue;
            }

            if let Ok(vk) = VerifyingKey::from_bytes(&key.public_key) {
                if vk.verify(data, &sig).is_ok() {
                    if self.require_cosign && key.key_type == KeyType::Secondary {
                        return Err(KeyValidationResult::RequiresCoSignature);
                    }
                    return Ok(key.key_id);
                }
            }
        }

        Err(KeyValidationResult::NotFound)
    }

    pub fn verify_multisig(
        &self,
        data: &[u8],
        signatures: &[([u8; 32], [u8; 64])],
        threshold: usize,
        timestamp: u64,
    ) -> Result<Vec<KeyId>, &'static str> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        if signatures.len() < threshold {
            return Err("insufficient signatures");
        }

        let mut verified_keys = Vec::new();
        let mut seen_key_ids = [[0u8; 32]; MAX_TRUSTED_KEYS];
        let mut seen_count = 0;

        for (pubkey, sig_bytes) in signatures {
            let key = match self.find_key_by_pubkey(pubkey) {
                Some(k) => k,
                None => continue,
            };

            let validation = key.is_valid_at(timestamp, self.minimum_version);
            if validation != KeyValidationResult::Valid {
                continue;
            }

            let mut already_seen = false;
            for i in 0..seen_count {
                if constant_time_eq(&seen_key_ids[i], &key.key_id) {
                    already_seen = true;
                    break;
                }
            }
            if already_seen {
                continue;
            }

            let sig = Signature::from_bytes(sig_bytes);
            if let Ok(vk) = VerifyingKey::from_bytes(&key.public_key) {
                if vk.verify(data, &sig).is_ok() {
                    verified_keys.push(key.key_id);
                    if seen_count < MAX_TRUSTED_KEYS {
                        seen_key_ids[seen_count] = key.key_id;
                        seen_count += 1;
                    }
                }
            }
        }

        if verified_keys.len() >= threshold {
            Ok(verified_keys)
        } else {
            Err("threshold not met")
        }
    }

    pub fn get_active_keys(&self, timestamp: u64) -> impl Iterator<Item = &TrustedKey> {
        self.keys[..self.key_count].iter().filter(move |k| {
            k.is_valid_at(timestamp, self.minimum_version) == KeyValidationResult::Valid
        })
    }

    pub fn get_primary_key(&self, timestamp: u64) -> Option<&TrustedKey> {
        self.get_active_keys(timestamp)
            .find(|k| k.key_type == KeyType::Primary)
    }
}

extern crate alloc;
use alloc::vec::Vec;

#[inline(never)]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub static KEYSTORE_V2: Mutex<KeystoreV2> = Mutex::new(KeystoreV2::new());

include!(concat!(env!("OUT_DIR"), "/keys_generated.rs"));

pub fn init_production_keystore() -> Result<usize, &'static str> {
    let mut store = KEYSTORE_V2.lock();

    let primary_key = TrustedKey::new(NONOS_PUBLIC_KEY, KEY_VERSION, 0, 0, KeyType::Primary);

    store.add_key(primary_key)?;

    Ok(store.key_count)
}

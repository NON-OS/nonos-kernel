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

use crate::crypto::keys::{KeyId, PK_LEN};

use super::types::{KeyType, KeyValidationResult, TrustedKey, MAX_TRUSTED_KEYS};
use super::util::constant_time_eq;

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

    pub fn get_active_keys(&self, timestamp: u64) -> impl Iterator<Item = &TrustedKey> {
        self.keys[..self.key_count].iter().filter(move |k| {
            k.is_valid_at(timestamp, self.minimum_version) == KeyValidationResult::Valid
        })
    }

    pub fn get_primary_key(&self, timestamp: u64) -> Option<&TrustedKey> {
        self.get_active_keys(timestamp)
            .find(|k| k.key_type == KeyType::Primary)
    }

    pub fn key_count(&self) -> usize {
        self.key_count
    }

    pub fn keys(&self) -> &[TrustedKey] {
        &self.keys[..self.key_count]
    }

    pub fn minimum_version(&self) -> u32 {
        self.minimum_version
    }

    pub fn require_cosign(&self) -> bool {
        self.require_cosign
    }
}

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
 * Key store implementation.
 *
 * Manages trusted Ed25519 public keys with version control and revocation.
 */

use super::types::{KeyId, KeyStatus, RevocationEntry, RevocationReason, MAX_KEYS, MAX_REVOKED, PK_LEN};
use super::util::{constant_time_eq, derive_keyid};

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

    pub fn add_key(&mut self, pubkey: &[u8; PK_LEN], version: u32) -> Result<KeyId, &'static str> {
        let id = derive_keyid(pubkey);

        if self.is_revoked(&id) {
            return Err("key revoked");
        }
        if version < self.minimum_version {
            return Err("version too old");
        }

        for i in 0..self.count {
            if constant_time_eq(&self.keys[i], pubkey) {
                if version > self.versions[i] {
                    self.versions[i] = version;
                }
                return Ok(id);
            }
        }

        if self.count >= MAX_KEYS {
            return Err("keystore full");
        }

        let idx = self.count;
        self.keys[idx] = *pubkey;
        self.versions[idx] = version;
        self.count += 1;
        Ok(id)
    }
}

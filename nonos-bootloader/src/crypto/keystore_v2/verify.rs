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
 * Signature verification with keystore.
 * Supports single-sig and multi-sig (threshold) verification.
 */

extern crate alloc;

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::crypto::keyring::KeyId;

use super::store::KeystoreV2;
use super::types::{KeyType, KeyValidationResult, MAX_TRUSTED_KEYS};
use super::util::constant_time_eq;

impl KeystoreV2 {
    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8; 64],
        timestamp: u64,
    ) -> Result<KeyId, KeyValidationResult> {
        let sig = Signature::from_bytes(signature);

        for key in self.keys() {
            let validation = key.is_valid_at(timestamp, self.minimum_version());
            if validation != KeyValidationResult::Valid {
                continue;
            }

            if let Ok(vk) = VerifyingKey::from_bytes(&key.public_key) {
                if vk.verify(data, &sig).is_ok() {
                    if self.require_cosign() && key.key_type == KeyType::Secondary {
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

            let validation = key.is_valid_at(timestamp, self.minimum_version());
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
}

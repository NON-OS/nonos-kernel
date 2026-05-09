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

use alloc::vec::Vec;

use crate::crypto::asymmetric::alg_id::{AlgId, MAX_PUBKEY_BYTES};

pub const TRUST_ANCHOR_SCHEMA_VERSION: u16 = 1;
pub const MAX_TRUST_ANCHOR_KEYS: usize = 4;
pub const MAX_REVOKED_CERT_SERIALS: usize = 256;
pub const MAX_REVOKED_NONOS_IDS: usize = 64;
pub const MAX_REVOKED_PUBLISHER_KEY_IDS: usize = 256;
pub const PUBLISHER_KEY_ID_LEN: usize = 16;
pub const NONOS_ID_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct TrustAnchorKey {
    pub algorithm: AlgId,
    pub pubkey: [u8; MAX_PUBKEY_BYTES],
    pub pubkey_len: u16,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

impl TrustAnchorKey {
    pub fn pubkey_bytes(&self) -> &[u8] {
        &self.pubkey[..self.pubkey_len as usize]
    }
}

#[derive(Debug, Clone)]
pub struct NonosTrustAnchorPolicy {
    pub schema_version: u16,
    pub trust_anchor_epoch: u64,
    pub keys: Vec<TrustAnchorKey>,
    pub revoked_cert_serials: Vec<u64>,
    pub revoked_nonos_ids: Vec<[u8; NONOS_ID_LEN]>,
    pub revoked_publisher_key_ids: Vec<[u8; PUBLISHER_KEY_ID_LEN]>,
    pub flags: u32,
}

impl NonosTrustAnchorPolicy {
    pub fn cert_serial_revoked(&self, serial: u64) -> bool {
        self.revoked_cert_serials.iter().any(|&s| s == serial)
    }

    pub fn nonos_id_revoked(&self, id: &[u8; NONOS_ID_LEN]) -> bool {
        self.revoked_nonos_ids.iter().any(|r| r == id)
    }

    pub fn publisher_key_id_revoked(&self, key_id: &[u8; PUBLISHER_KEY_ID_LEN]) -> bool {
        self.revoked_publisher_key_ids.iter().any(|r| r == key_id)
    }

    pub fn keys_for(&self, alg: AlgId) -> impl Iterator<Item = &TrustAnchorKey> + '_ {
        self.keys.iter().filter(move |k| k.algorithm == alg)
    }
}

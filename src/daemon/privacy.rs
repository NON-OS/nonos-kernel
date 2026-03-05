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

//! Privacy features: stealth addresses, ZK identity.

use crate::crypto::{blake3_hash, get_random_bytes};

pub const MAX_IDENTITIES: usize = 8;

#[derive(Clone, Copy)]
pub struct ZkIdentity {
    pub id: [u8; 32],
    pub commitment: [u8; 32],
    pub active: bool,
    pub created_epoch: u64,
}

impl ZkIdentity {
    pub const fn empty() -> Self {
        Self {
            id: [0u8; 32],
            commitment: [0u8; 32],
            active: false,
            created_epoch: 0,
        }
    }

    pub fn generate(epoch: u64) -> Self {
        let random = get_random_bytes();
        let id = blake3_hash(&random);

        let mut commitment_input = [0u8; 64];
        commitment_input[..32].copy_from_slice(&id);
        commitment_input[32..].copy_from_slice(&random);
        let commitment = blake3_hash(&commitment_input);

        Self {
            id,
            commitment,
            active: true,
            created_epoch: epoch,
        }
    }

    pub fn short_id(&self) -> [u8; 16] {
        let mut short = [0u8; 16];
        for i in 0..16 {
            let nibble = if i % 2 == 0 {
                self.id[i / 2] >> 4
            } else {
                self.id[i / 2] & 0xF
            };
            short[i] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
        }
        short
    }
}

#[derive(Clone, Copy)]
pub struct PrivacyState {
    pub identities: [ZkIdentity; MAX_IDENTITIES],
    pub identity_count: usize,
    pub active_identity: usize,
    pub stealth_enabled: bool,
    pub fingerprint_protection: bool,
    pub request_padding: bool,
}

impl PrivacyState {
    pub const fn new() -> Self {
        Self {
            identities: [ZkIdentity::empty(); MAX_IDENTITIES],
            identity_count: 0,
            active_identity: 0,
            stealth_enabled: true,
            fingerprint_protection: true,
            request_padding: true,
        }
    }

    pub fn create_identity(&mut self, epoch: u64) -> Option<usize> {
        if self.identity_count >= MAX_IDENTITIES {
            return None;
        }

        let identity = ZkIdentity::generate(epoch);
        self.identities[self.identity_count] = identity;
        let idx = self.identity_count;
        self.identity_count += 1;

        if self.identity_count == 1 {
            self.active_identity = 0;
        }

        Some(idx)
    }

    pub fn switch_identity(&mut self, index: usize) -> bool {
        if index >= self.identity_count {
            return false;
        }
        if !self.identities[index].active {
            return false;
        }
        self.active_identity = index;
        true
    }

    pub fn deactivate_identity(&mut self, index: usize) -> bool {
        if index >= self.identity_count {
            return false;
        }
        self.identities[index].active = false;
        true
    }

    pub fn get_active(&self) -> Option<&ZkIdentity> {
        if self.identity_count == 0 {
            return None;
        }
        Some(&self.identities[self.active_identity])
    }

    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.identity_count {
            if self.identities[i].active {
                count += 1;
            }
        }
        count
    }

    pub fn enable_stealth(&mut self) {
        self.stealth_enabled = true;
    }

    pub fn disable_stealth(&mut self) {
        self.stealth_enabled = false;
    }

    pub fn set_fingerprint_protection(&mut self, enabled: bool) {
        self.fingerprint_protection = enabled;
    }

    pub fn set_request_padding(&mut self, enabled: bool) {
        self.request_padding = enabled;
    }
}

impl Default for PrivacyState {
    fn default() -> Self {
        Self::new()
    }
}

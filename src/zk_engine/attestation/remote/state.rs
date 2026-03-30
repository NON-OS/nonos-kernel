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

use alloc::vec::Vec;

pub struct RemoteAttestationClient {
    pub(super) trusted_keys: Vec<[u8; 32]>,
    pub(super) current_nonce: [u8; 32],
    pub(super) last_attestation_time: u64,
    pub(super) min_attestation_interval_ms: u64,
}

impl RemoteAttestationClient {
    pub fn new() -> Self {
        let entropy = crate::crypto::entropy::get_entropy(32);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&entropy[..32]);
        Self {
            trusted_keys: Vec::new(),
            current_nonce: nonce,
            last_attestation_time: 0,
            min_attestation_interval_ms: 1000,
        }
    }
}

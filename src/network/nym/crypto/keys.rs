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

use super::curve::x25519_scalar_mult;
use super::kdf::hkdf_sha256;

#[derive(Clone)]
pub struct SphinxKeys {
    pub header_key: [u8; 32],
    pub payload_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub routing_key: [u8; 32],
    pub blinding_factor: [u8; 32],
}

pub fn derive_sphinx_keys(shared_secret: &[u8; 32]) -> SphinxKeys {
    let expanded = hkdf_sha256(shared_secret, b"nym-sphinx-keys", b"", 160);
    let mut keys = SphinxKeys {
        header_key: [0u8; 32],
        payload_key: [0u8; 32],
        mac_key: [0u8; 32],
        routing_key: [0u8; 32],
        blinding_factor: [0u8; 32],
    };
    keys.header_key.copy_from_slice(&expanded[0..32]);
    keys.payload_key.copy_from_slice(&expanded[32..64]);
    keys.mac_key.copy_from_slice(&expanded[64..96]);
    keys.routing_key.copy_from_slice(&expanded[96..128]);
    keys.blinding_factor.copy_from_slice(&expanded[128..160]);
    keys
}

pub fn blind_public_key(pubkey: &[u8; 32], blinding: &[u8; 32]) -> [u8; 32] {
    x25519_scalar_mult(blinding, pubkey)
}

impl SphinxKeys {
    pub fn zeroize(&mut self) {
        self.header_key = [0u8; 32];
        self.payload_key = [0u8; 32];
        self.mac_key = [0u8; 32];
        self.routing_key = [0u8; 32];
        self.blinding_factor = [0u8; 32];
    }
}

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

use crate::crypto::secp256k1::{self, PublicKey};
use crate::crypto::sha3::keccak256;

#[derive(Clone, Debug)]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    pub fn from_bytes(bytes: &[u8; 20]) -> Self {
        Self(*bytes)
    }

    pub fn from_public_key(pk: &PublicKey) -> Self {
        Self(secp256k1::eth_address(pk))
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    pub fn to_checksum_string(&self) -> [u8; 42] {
        let mut result = [0u8; 42];
        result[0] = b'0';
        result[1] = b'x';

        let hex_chars: &[u8; 16] = b"0123456789abcdef";
        let mut hex_addr = [0u8; 40];
        for i in 0..20 {
            hex_addr[i * 2] = hex_chars[(self.0[i] >> 4) as usize];
            hex_addr[i * 2 + 1] = hex_chars[(self.0[i] & 0x0f) as usize];
        }

        let hash = keccak256(&hex_addr);

        for i in 0..40 {
            let hash_nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };

            result[2 + i] = if hash_nibble >= 8 && hex_addr[i] >= b'a' && hex_addr[i] <= b'f' {
                hex_addr[i] - 32
            } else {
                hex_addr[i]
            };
        }

        result
    }
}

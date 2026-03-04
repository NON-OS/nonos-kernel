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

use crate::crypto::secp256k1::{self, SecretKey, PublicKey};
use crate::crypto::blake3_hash;

#[derive(Clone)]
pub(crate) struct StealthKeyPair {
    pub(crate) spend_secret: SecretKey,
    pub(crate) spend_public: PublicKey,
    pub(crate) view_secret: SecretKey,
    pub(crate) view_public: PublicKey,
}

impl StealthKeyPair {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let spend_seed = blake3_hash(&[&seed[..], b"spend"].concat());
        let view_seed = blake3_hash(&[&seed[..], b"view"].concat());

        let mut spend_secret = [0u8; 32];
        spend_secret.copy_from_slice(&spend_seed);

        let mut view_secret = [0u8; 32];
        view_secret.copy_from_slice(&view_seed);

        let spend_public = secp256k1::public_key_from_secret(&spend_secret).unwrap_or([0u8; 65]);
        let view_public = secp256k1::public_key_from_secret(&view_secret).unwrap_or([0u8; 65]);

        Self {
            spend_secret,
            spend_public,
            view_secret,
            view_public,
        }
    }

    pub(crate) fn meta_address(&self) -> StealthMetaAddress {
        StealthMetaAddress {
            spend_pubkey: self.spend_public,
            view_pubkey: self.view_public,
        }
    }
}

#[derive(Clone)]
pub(crate) struct StealthMetaAddress {
    pub(crate) spend_pubkey: PublicKey,
    pub(crate) view_pubkey: PublicKey,
}

impl StealthMetaAddress {
    pub(crate) fn encode(&self) -> [u8; 140] {
        let mut result = [0u8; 140];
        result[..8].copy_from_slice(b"st:eth:0");
        result[8] = b'x';

        let hex_chars: &[u8; 16] = b"0123456789abcdef";
        for i in 0..65 {
            result[9 + i * 2] = hex_chars[(self.spend_pubkey[i] >> 4) as usize];
            result[9 + i * 2 + 1] = hex_chars[(self.spend_pubkey[i] & 0x0f) as usize];
        }

        for i in 0..65 {
            let offset = 9 + 130 + i * 2;
            if offset + 1 < 140 {
                result[offset] = hex_chars[(self.view_pubkey[i] >> 4) as usize];
            }
        }

        result
    }

}

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
use crate::crypto::blake3_hash;
use crate::crypto::secp256k1::{self, PublicKey, SecretKey};

const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone)]
pub(crate) struct StealthKeyPair {
    pub spend_secret: SecretKey,
    pub spend_public: PublicKey,
    pub view_secret: SecretKey,
    pub view_public: PublicKey,
}

impl StealthKeyPair {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let ss = blake3_hash(&[&seed[..], b"spend"].concat());
        let vs = blake3_hash(&[&seed[..], b"view"].concat());
        let mut spend_secret = [0u8; 32];
        spend_secret.copy_from_slice(&ss);
        let mut view_secret = [0u8; 32];
        view_secret.copy_from_slice(&vs);
        let spend_public = secp256k1::public_key_from_secret(&spend_secret).unwrap_or([0u8; 65]);
        let view_public = secp256k1::public_key_from_secret(&view_secret).unwrap_or([0u8; 65]);
        Self { spend_secret, spend_public, view_secret, view_public }
    }
    pub(crate) fn meta_address(&self) -> StealthMetaAddress {
        StealthMetaAddress { spend_pubkey: self.spend_public, view_pubkey: self.view_public }
    }
    pub(crate) fn derive_stealth_address(&self, eph: &[u8; 32]) -> [u8; 20] {
        let shared =
            blake3_hash(&[&self.view_secret[..], &eph[..], b"NONOS:STEALTH:SHARED"].concat());
        let derived = blake3_hash(&[&self.spend_secret[..], &shared[..]].concat());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&derived[..20]);
        addr
    }
}

#[derive(Clone)]
pub(crate) struct StealthMetaAddress {
    pub spend_pubkey: PublicKey,
    pub view_pubkey: PublicKey,
}

impl StealthMetaAddress {
    pub(crate) fn encode(&self) -> [u8; 140] {
        let mut r = [0u8; 140];
        r[..9].copy_from_slice(b"st:eth:0x");
        for i in 0..65 {
            r[9 + i * 2] = HEX[(self.spend_pubkey[i] >> 4) as usize];
            r[9 + i * 2 + 1] = HEX[(self.spend_pubkey[i] & 0x0f) as usize];
        }
        for i in 0..65 {
            let o = 9 + 130 + i * 2;
            if o + 1 < 140 {
                r[o] = HEX[(self.view_pubkey[i] >> 4) as usize];
            }
        }
        r
    }
}

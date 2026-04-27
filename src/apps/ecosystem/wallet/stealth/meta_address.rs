// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::utils::{compress_pubkey, decompress_pubkey, hex_to_bytes};
use crate::crypto::asymmetric::secp256k1::PublicKey;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::string::String;

#[derive(Clone)]
pub struct StealthMetaAddress {
    pub(super) spending_pubkey: PublicKey,
    pub(super) viewing_pubkey: PublicKey,
}

impl StealthMetaAddress {
    pub fn new(spending_pubkey: PublicKey, viewing_pubkey: PublicKey) -> Self {
        Self { spending_pubkey, viewing_pubkey }
    }

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 130 && bytes.len() != 66 {
            return Err(CryptoError::InvalidLength);
        }
        if bytes.len() == 130 {
            if bytes[0] != 0x04 || bytes[65] != 0x04 {
                return Err(CryptoError::InvalidInput);
            }
            let (mut spending, mut viewing) = ([0u8; 65], [0u8; 65]);
            spending.copy_from_slice(&bytes[0..65]);
            viewing.copy_from_slice(&bytes[65..130]);
            Ok(Self { spending_pubkey: spending, viewing_pubkey: viewing })
        } else {
            Ok(Self {
                spending_pubkey: decompress_pubkey(&bytes[0..33])?,
                viewing_pubkey: decompress_pubkey(&bytes[33..66])?,
            })
        }
    }

    pub fn to_bytes(&self) -> [u8; 130] {
        let mut bytes = [0u8; 130];
        bytes[0..65].copy_from_slice(&self.spending_pubkey);
        bytes[65..130].copy_from_slice(&self.viewing_pubkey);
        bytes
    }

    pub fn to_compressed(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[0..33].copy_from_slice(&compress_pubkey(&self.spending_pubkey));
        bytes[33..66].copy_from_slice(&compress_pubkey(&self.viewing_pubkey));
        bytes
    }

    pub fn encode(&self) -> String {
        let mut hex = String::with_capacity(272);
        hex.push_str("st:eth:0x");
        for byte in &self.to_bytes() {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }

    pub fn decode(encoded: &str) -> CryptoResult<Self> {
        let encoded = encoded.trim();
        let hex = if encoded.starts_with("st:eth:0x") {
            &encoded[9..]
        } else if encoded.starts_with("st:eth:") {
            &encoded[7..]
        } else if encoded.starts_with("0x") {
            &encoded[2..]
        } else {
            encoded
        };
        if hex.len() != 132 && hex.len() != 260 {
            return Err(CryptoError::InvalidLength);
        }
        Self::from_bytes(&hex_to_bytes(hex)?)
    }

    pub fn spending_pubkey(&self) -> &PublicKey {
        &self.spending_pubkey
    }
    pub fn viewing_pubkey(&self) -> &PublicKey {
        &self.viewing_pubkey
    }
}

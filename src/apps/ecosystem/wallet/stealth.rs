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

//! EIP-5564 Stealth Addresses implementation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::crypto::asymmetric::secp256k1::{
    multiply_point, point_add, public_key_from_secret, scalar_multiply, PublicKey, SecretKey,
};
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

const GENERATOR: [u8; 65] = [
    0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
    0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
    0xB8,
];

#[derive(Clone)]
pub struct StealthKeyPair {
    spending_key: SecretKey,
    viewing_key: SecretKey,
    spending_pubkey: PublicKey,
    viewing_pubkey: PublicKey,
}

impl StealthKeyPair {
    pub fn generate() -> CryptoResult<Self> {
        let spending_key = generate_random_key()?;
        let viewing_key = generate_random_key()?;

        let spending_pubkey = public_key_from_secret(&spending_key)
            .ok_or(CryptoError::InvalidInput)?;
        let viewing_pubkey = public_key_from_secret(&viewing_key)
            .ok_or(CryptoError::InvalidInput)?;

        Ok(Self {
            spending_key,
            viewing_key,
            spending_pubkey,
            viewing_pubkey,
        })
    }

    pub fn from_keys(spending_key: SecretKey, viewing_key: SecretKey) -> CryptoResult<Self> {
        let spending_pubkey = public_key_from_secret(&spending_key)
            .ok_or(CryptoError::InvalidInput)?;
        let viewing_pubkey = public_key_from_secret(&viewing_key)
            .ok_or(CryptoError::InvalidInput)?;

        Ok(Self {
            spending_key,
            viewing_key,
            spending_pubkey,
            viewing_pubkey,
        })
    }

    pub fn from_master_key(master_key: &[u8; 32]) -> CryptoResult<Self> {
        let spending_preimage = [master_key.as_slice(), b"stealth-spending"].concat();
        let viewing_preimage = [master_key.as_slice(), b"stealth-viewing"].concat();

        let spending_key = keccak256(&spending_preimage);
        let viewing_key = keccak256(&viewing_preimage);

        Self::from_keys(spending_key, viewing_key)
    }

    pub fn spending_pubkey(&self) -> &PublicKey {
        &self.spending_pubkey
    }

    pub fn viewing_pubkey(&self) -> &PublicKey {
        &self.viewing_pubkey
    }

    pub fn meta_address(&self) -> StealthMetaAddress {
        StealthMetaAddress {
            spending_pubkey: self.spending_pubkey,
            viewing_pubkey: self.viewing_pubkey,
        }
    }

    pub fn derive_stealth_private_key(
        &self,
        ephemeral_pubkey: &PublicKey,
    ) -> CryptoResult<SecretKey> {
        let shared_secret = multiply_point(ephemeral_pubkey, &self.viewing_key)?;

        let mut hash_input = Vec::with_capacity(65);
        hash_input.extend_from_slice(&shared_secret);
        let hashed_secret = keccak256(&hash_input);

        let stealth_private_key = scalar_add(&self.spending_key, &hashed_secret)?;

        Ok(stealth_private_key)
    }

    pub fn can_spend(&self, stealth_address: &[u8; 20], ephemeral_pubkey: &PublicKey) -> bool {
        match self.derive_stealth_private_key(ephemeral_pubkey) {
            Ok(priv_key) => {
                if let Some(pub_key) = public_key_from_secret(&priv_key) {
                    let derived_addr = pubkey_to_address(&pub_key);
                    derived_addr == *stealth_address
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }
}

impl Drop for StealthKeyPair {
    fn drop(&mut self) {
        for byte in self.spending_key.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        for byte in self.viewing_key.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct StealthMetaAddress {
    spending_pubkey: PublicKey,
    viewing_pubkey: PublicKey,
}

impl StealthMetaAddress {
    pub fn new(spending_pubkey: PublicKey, viewing_pubkey: PublicKey) -> Self {
        Self {
            spending_pubkey,
            viewing_pubkey,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 130 && bytes.len() != 66 {
            return Err(CryptoError::InvalidLength);
        }

        if bytes.len() == 130 {
            if bytes[0] != 0x04 || bytes[65] != 0x04 {
                return Err(CryptoError::InvalidInput);
            }

            let mut spending = [0u8; 65];
            let mut viewing = [0u8; 65];
            spending.copy_from_slice(&bytes[0..65]);
            viewing.copy_from_slice(&bytes[65..130]);

            Ok(Self {
                spending_pubkey: spending,
                viewing_pubkey: viewing,
            })
        } else {
            let spending = decompress_pubkey(&bytes[0..33])?;
            let viewing = decompress_pubkey(&bytes[33..66])?;

            Ok(Self {
                spending_pubkey: spending,
                viewing_pubkey: viewing,
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
        let compressed = self.to_compressed();
        let mut hex = String::with_capacity(136);
        hex.push_str("st:eth:0x");
        for byte in &compressed {
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

        let bytes = hex_to_bytes(hex)?;
        Self::from_bytes(&bytes)
    }

    pub fn spending_pubkey(&self) -> &PublicKey {
        &self.spending_pubkey
    }

    pub fn viewing_pubkey(&self) -> &PublicKey {
        &self.viewing_pubkey
    }
}

#[derive(Clone)]
pub struct GeneratedStealthAddress {
    pub stealth_address: [u8; 20],
    pub ephemeral_pubkey: PublicKey,
    pub view_tag: u8,
}

impl GeneratedStealthAddress {
    pub fn stealth_address_hex(&self) -> String {
        let mut hex = String::with_capacity(42);
        hex.push_str("0x");
        for byte in &self.stealth_address {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }

    pub fn ephemeral_pubkey_hex(&self) -> String {
        let mut hex = String::with_capacity(132);
        hex.push_str("0x");
        for byte in &self.ephemeral_pubkey {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }
}

pub fn generate_stealth_address(
    meta_address: &StealthMetaAddress,
) -> CryptoResult<GeneratedStealthAddress> {
    let ephemeral_key = generate_random_key()?;
    let ephemeral_pubkey = public_key_from_secret(&ephemeral_key)
        .ok_or(CryptoError::InvalidInput)?;

    let shared_secret = multiply_point(&meta_address.viewing_pubkey, &ephemeral_key)?;

    let mut hash_input = Vec::with_capacity(65);
    hash_input.extend_from_slice(&shared_secret);
    let hashed_secret = keccak256(&hash_input);

    let view_tag = hashed_secret[0];

    let hashed_secret_point = scalar_multiply(&GENERATOR, &hashed_secret)?;

    let stealth_pubkey = point_add(&meta_address.spending_pubkey, &hashed_secret_point)?;

    let stealth_address = pubkey_to_address(&stealth_pubkey);

    Ok(GeneratedStealthAddress {
        stealth_address,
        ephemeral_pubkey,
        view_tag,
    })
}

pub struct Announcement {
    pub stealth_address: [u8; 20],
    pub ephemeral_pubkey: PublicKey,
    pub view_tag: u8,
    pub metadata: Vec<u8>,
}

pub fn scan_announcements(
    keys: &StealthKeyPair,
    announcements: &[Announcement],
) -> Vec<(usize, SecretKey, [u8; 20])> {
    let mut found = Vec::new();

    for (idx, announcement) in announcements.iter().enumerate() {
        let shared_secret = match multiply_point(&announcement.ephemeral_pubkey, &keys.viewing_key)
        {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut hash_input = Vec::with_capacity(65);
        hash_input.extend_from_slice(&shared_secret);
        let hashed_secret = keccak256(&hash_input);

        if hashed_secret[0] != announcement.view_tag {
            continue;
        }

        let stealth_private_key = match scalar_add(&keys.spending_key, &hashed_secret) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let stealth_pubkey = match public_key_from_secret(&stealth_private_key) {
            Some(pk) => pk,
            None => continue,
        };
        let derived_address = pubkey_to_address(&stealth_pubkey);

        if derived_address == announcement.stealth_address {
            found.push((idx, stealth_private_key, derived_address));
        }
    }

    found
}

pub fn compute_view_tag(shared_secret: &[u8; 65]) -> u8 {
    let hash = keccak256(shared_secret);
    hash[0]
}

fn generate_random_key() -> CryptoResult<SecretKey> {
    let mut key = [0u8; 32];
    crate::crypto::random::fill_bytes(&mut key)?;

    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] {
            return Ok(key);
        }
        if key[i] > SECP256K1_ORDER[i] {
            return generate_random_key();
        }
    }

    generate_random_key()
}

fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    let mut result = [0u64; 4];
    let mut carry = 0u64;

    for i in (0..4).rev() {
        let idx = i * 8;
        let a_chunk = u64::from_be_bytes([
            a[idx],
            a[idx + 1],
            a[idx + 2],
            a[idx + 3],
            a[idx + 4],
            a[idx + 5],
            a[idx + 6],
            a[idx + 7],
        ]);
        let b_chunk = u64::from_be_bytes([
            b[idx],
            b[idx + 1],
            b[idx + 2],
            b[idx + 3],
            b[idx + 4],
            b[idx + 5],
            b[idx + 6],
            b[idx + 7],
        ]);

        let (sum1, c1) = a_chunk.overflowing_add(b_chunk);
        let (sum2, c2) = sum1.overflowing_add(carry);
        result[i] = sum2;
        carry = (c1 as u64) + (c2 as u64);
    }

    let order = [
        u64::from_be_bytes([
            SECP256K1_ORDER[0],
            SECP256K1_ORDER[1],
            SECP256K1_ORDER[2],
            SECP256K1_ORDER[3],
            SECP256K1_ORDER[4],
            SECP256K1_ORDER[5],
            SECP256K1_ORDER[6],
            SECP256K1_ORDER[7],
        ]),
        u64::from_be_bytes([
            SECP256K1_ORDER[8],
            SECP256K1_ORDER[9],
            SECP256K1_ORDER[10],
            SECP256K1_ORDER[11],
            SECP256K1_ORDER[12],
            SECP256K1_ORDER[13],
            SECP256K1_ORDER[14],
            SECP256K1_ORDER[15],
        ]),
        u64::from_be_bytes([
            SECP256K1_ORDER[16],
            SECP256K1_ORDER[17],
            SECP256K1_ORDER[18],
            SECP256K1_ORDER[19],
            SECP256K1_ORDER[20],
            SECP256K1_ORDER[21],
            SECP256K1_ORDER[22],
            SECP256K1_ORDER[23],
        ]),
        u64::from_be_bytes([
            SECP256K1_ORDER[24],
            SECP256K1_ORDER[25],
            SECP256K1_ORDER[26],
            SECP256K1_ORDER[27],
            SECP256K1_ORDER[28],
            SECP256K1_ORDER[29],
            SECP256K1_ORDER[30],
            SECP256K1_ORDER[31],
        ]),
    ];

    let mut needs_reduction = carry > 0;
    if !needs_reduction {
        for i in 0..4 {
            if result[i] > order[i] {
                needs_reduction = true;
                break;
            }
            if result[i] < order[i] {
                break;
            }
        }
    }

    if needs_reduction {
        let mut borrow = 0u64;
        for i in (0..4).rev() {
            let (diff, b1) = result[i].overflowing_sub(order[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = result[i].to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }

    Ok(out)
}

fn pubkey_to_address(pubkey: &PublicKey) -> [u8; 20] {
    let hash = keccak256(&pubkey[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

fn compress_pubkey(pubkey: &PublicKey) -> [u8; 33] {
    let mut compressed = [0u8; 33];
    let y_is_odd = (pubkey[64] & 1) == 1;
    compressed[0] = if y_is_odd { 0x03 } else { 0x02 };
    compressed[1..33].copy_from_slice(&pubkey[1..33]);
    compressed
}

fn decompress_pubkey(compressed: &[u8]) -> CryptoResult<PublicKey> {
    if compressed.len() != 33 {
        return Err(CryptoError::InvalidLength);
    }

    if compressed[0] != 0x02 && compressed[0] != 0x03 {
        return Err(CryptoError::InvalidInput);
    }

    crate::crypto::asymmetric::secp256k1::decompress_pubkey(compressed)
}

fn hex_to_bytes(hex: &str) -> CryptoResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::InvalidLength);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| CryptoError::InvalidInput)?;
        bytes.push(byte);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_key_generation() {
        let keys = StealthKeyPair::generate().unwrap();
        assert_eq!(keys.spending_pubkey[0], 0x04);
        assert_eq!(keys.viewing_pubkey[0], 0x04);
    }

    #[test]
    fn test_meta_address_encoding() {
        let keys = StealthKeyPair::generate().unwrap();
        let meta = keys.meta_address();

        let encoded = meta.encode();
        assert!(encoded.starts_with("st:eth:0x"));

        let decoded = StealthMetaAddress::decode(&encoded).unwrap();
        assert_eq!(decoded.spending_pubkey, meta.spending_pubkey);
        assert_eq!(decoded.viewing_pubkey, meta.viewing_pubkey);
    }

    #[test]
    fn test_stealth_address_derivation() {
        let recipient_keys = StealthKeyPair::generate().unwrap();
        let meta = recipient_keys.meta_address();

        let generated = generate_stealth_address(&meta).unwrap();

        let can_spend = recipient_keys.can_spend(
            &generated.stealth_address,
            &generated.ephemeral_pubkey,
        );
        assert!(can_spend);
    }
}

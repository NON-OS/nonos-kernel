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
use super::constants::SECP256K1_ORDER;
use crate::crypto::asymmetric::secp256k1::{PublicKey, SecretKey};
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::vec::Vec;

pub(super) fn generate_random_key() -> CryptoResult<SecretKey> {
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

pub(super) fn pubkey_to_address(pubkey: &PublicKey) -> [u8; 20] {
    let hash = keccak256(&pubkey[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

pub(super) fn fallback_stealth_address(
    spending_pubkey: &PublicKey,
    shared_secret: &[u8; 65],
) -> [u8; 20] {
    let mut input = Vec::with_capacity(130);
    input.extend_from_slice(spending_pubkey);
    input.extend_from_slice(shared_secret);
    let mut address = [0u8; 20];
    address.copy_from_slice(&keccak256(&input)[12..32]);
    address
}

pub(super) fn fallback_shared_secret(
    viewing_pubkey: &PublicKey,
    ephemeral_pubkey: &PublicKey,
) -> [u8; 65] {
    let mut input = Vec::with_capacity(130);
    input.extend_from_slice(viewing_pubkey);
    input.extend_from_slice(ephemeral_pubkey);
    let h1 = keccak256(&input);
    input.clear();
    input.extend_from_slice(ephemeral_pubkey);
    input.extend_from_slice(viewing_pubkey);
    let h2 = keccak256(&input);
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&h1);
    out[33..65].copy_from_slice(&h2);
    out
}

pub(super) fn compress_pubkey(pubkey: &PublicKey) -> [u8; 33] {
    let mut compressed = [0u8; 33];
    compressed[0] = if (pubkey[64] & 1) == 1 { 0x03 } else { 0x02 };
    compressed[1..33].copy_from_slice(&pubkey[1..33]);
    compressed
}

pub(super) fn decompress_pubkey(compressed: &[u8]) -> CryptoResult<PublicKey> {
    if compressed.len() != 33 {
        return Err(CryptoError::InvalidLength);
    }
    if compressed[0] != 0x02 && compressed[0] != 0x03 {
        return Err(CryptoError::InvalidInput);
    }
    crate::crypto::asymmetric::secp256k1::decompress_pubkey(compressed)
}

pub(super) fn hex_to_bytes(hex: &str) -> CryptoResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| CryptoError::InvalidInput)?);
    }
    Ok(bytes)
}

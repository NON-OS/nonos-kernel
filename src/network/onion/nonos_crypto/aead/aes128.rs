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

use crate::crypto::{entropy, hash};
use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub fn aes128_gcm_seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 16 {
        return Err(OnionError::CryptoError);
    }
    let mut nonce = [0u8; 12];
    let entropy_bytes = entropy::get_entropy(12);
    nonce.copy_from_slice(&entropy_bytes[..12]);
    let mut key256 = [0u8; 32];
    key256[..16].copy_from_slice(key);
    let derived = hash::hmac_sha256(key, b"AES-128-GCM-EXPAND");
    key256[16..].copy_from_slice(&derived[..16]);
    let encrypted = crate::crypto::aes_gcm::aes256_gcm_encrypt(&key256, &nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)?;
    let mut result = Vec::with_capacity(12 + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

pub fn aes128_gcm_open(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 16 || ciphertext.len() < 12 {
        return Err(OnionError::CryptoError);
    }
    let nonce = &ciphertext[..12];
    let actual_ciphertext = &ciphertext[12..];
    let mut key256 = [0u8; 32];
    key256[..16].copy_from_slice(key);
    let derived = hash::hmac_sha256(key, b"AES-128-GCM-EXPAND");
    key256[16..].copy_from_slice(&derived[..16]);
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce);
    crate::crypto::aes_gcm::aes256_gcm_decrypt(&key256, &nonce_array, aad, actual_ciphertext)
        .map_err(|_| OnionError::CryptoError)
}

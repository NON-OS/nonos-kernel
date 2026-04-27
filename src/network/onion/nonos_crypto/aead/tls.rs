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

use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub fn tls_aes128_gcm_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if key.len() != 16 {
        return Err(OnionError::CryptoError);
    }
    let mut key128 = [0u8; 16];
    key128.copy_from_slice(key);
    crate::crypto::aes_gcm::aes128_gcm_encrypt(&key128, nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_aes128_gcm_open(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if key.len() != 16 {
        return Err(OnionError::CryptoError);
    }
    let mut key128 = [0u8; 16];
    key128.copy_from_slice(key);
    crate::crypto::aes_gcm::aes128_gcm_decrypt(&key128, nonce, aad, ciphertext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_chacha20poly1305_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);
    crate::crypto::chacha20poly1305::aead_encrypt(&key_bytes, nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_chacha20poly1305_open(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);
    crate::crypto::chacha20poly1305::aead_decrypt(&key_bytes, nonce, aad, ciphertext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_aes256_gcm_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }
    let mut key256 = [0u8; 32];
    key256.copy_from_slice(key);
    crate::crypto::aes_gcm::aes256_gcm_encrypt(&key256, nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_aes256_gcm_open(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }
    let mut key256 = [0u8; 32];
    key256.copy_from_slice(key);
    crate::crypto::aes_gcm::aes256_gcm_decrypt(&key256, nonce, aad, ciphertext)
        .map_err(|_| OnionError::CryptoError)
}

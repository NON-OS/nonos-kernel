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
use crate::crypto::{hash, entropy};
use crate::network::onion::OnionError;

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

pub fn chacha20poly1305_seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }

    let mut nonce = [0u8; 12];
    let entropy_bytes = entropy::get_entropy(12);
    nonce.copy_from_slice(&entropy_bytes[..12]);

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);

    let encrypted = crate::crypto::chacha20poly1305::aead_encrypt(&key_bytes, &nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)?;

    let mut result = Vec::with_capacity(12 + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

pub fn chacha20poly1305_open(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 || ciphertext.len() < 12 {
        return Err(OnionError::CryptoError);
    }

    let nonce = &ciphertext[..12];
    let actual_ciphertext = &ciphertext[12..];

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);

    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce);

    crate::crypto::chacha20poly1305::aead_decrypt(&key_bytes, &nonce_array, aad, actual_ciphertext)
        .map_err(|_| OnionError::CryptoError)
}


pub fn tls_aes128_gcm_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 16 {
        return Err(OnionError::CryptoError);
    }

    let mut key256 = [0u8; 32];
    key256[..16].copy_from_slice(key);
    let derived = hash::hmac_sha256(key, b"AES-128-GCM-EXPAND");
    key256[16..].copy_from_slice(&derived[..16]);

    crate::crypto::aes_gcm::aes256_gcm_encrypt(&key256, nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_aes128_gcm_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 16 {
        return Err(OnionError::CryptoError);
    }

    let mut key256 = [0u8; 32];
    key256[..16].copy_from_slice(key);
    let derived = hash::hmac_sha256(key, b"AES-128-GCM-EXPAND");
    key256[16..].copy_from_slice(&derived[..16]);

    crate::crypto::aes_gcm::aes256_gcm_decrypt(&key256, nonce, aad, ciphertext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_chacha20poly1305_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);

    crate::crypto::chacha20poly1305::aead_encrypt(&key_bytes, nonce, aad, plaintext)
        .map_err(|_| OnionError::CryptoError)
}

pub fn tls_chacha20poly1305_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
    if key.len() != 32 {
        return Err(OnionError::CryptoError);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);

    crate::crypto::chacha20poly1305::aead_decrypt(&key_bytes, nonce, aad, ciphertext)
        .map_err(|_| OnionError::CryptoError)
}

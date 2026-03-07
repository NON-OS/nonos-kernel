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

/*
CryptoFS cryptographic operations. Key derivation via PBKDF2-SHA256 with 100k
iterations for brute-force resistance. Encryption uses ChaCha20-Poly1305 AEAD
with random 96-bit nonces. File paths mixed into KDF salt for per-file keys.
*/

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::chacha20poly1305::{aead_encrypt, aead_decrypt};
use crate::crypto::rng::fill_random_bytes;
use crate::crypto::util::hmac::pbkdf2_hmac_sha256;

use super::error::{CryptoFsError, CryptoResult};
use super::types::*;

const KDF_ITERATIONS: u32 = 100_000;

pub fn derive_key(path: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let path_bytes = path.as_bytes();
    let mut kdf_salt = Vec::with_capacity(SALT_SIZE + KEY_DERIVATION_CONTEXT.len());
    kdf_salt.extend_from_slice(salt);
    kdf_salt.extend_from_slice(KEY_DERIVATION_CONTEXT);

    let derived = pbkdf2_hmac_sha256(path_bytes, &kdf_salt, KDF_ITERATIONS, KEY_SIZE);

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&derived);
    key
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    fill_random_bytes(&mut nonce);
    nonce
}

pub fn encrypt_data(data: &[u8], key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> CryptoResult<Vec<u8>> {
    let ct_and_tag = aead_encrypt(key, nonce, FILE_AAD, data)
        .map_err(|_| CryptoFsError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ct_and_tag.len());
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ct_and_tag);
    Ok(result)
}

pub fn decrypt_data(encrypted: &[u8], key: &[u8; KEY_SIZE]) -> CryptoResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoFsError::DataTooShort);
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&encrypted[0..NONCE_SIZE]);

    let ct_and_tag = &encrypted[NONCE_SIZE..];

    aead_decrypt(key, &nonce, FILE_AAD, ct_and_tag)
        .map_err(|_| CryptoFsError::AuthenticationFailed)
}

pub fn validate_path(path: &str) -> CryptoResult<()> {
    if path.is_empty() {
        return Err(CryptoFsError::InvalidPath);
    }
    if path.len() > MAX_PATH_LEN {
        return Err(CryptoFsError::PathTooLong);
    }
    if path.bytes().any(|b| b == 0) {
        return Err(CryptoFsError::InvalidPath);
    }
    Ok(())
}

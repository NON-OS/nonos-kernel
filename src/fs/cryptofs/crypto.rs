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

use alloc::vec::Vec;

use crate::crypto::chacha20poly1305::{aead_encrypt, aead_decrypt};
use crate::crypto::rng::fill_random_bytes;
use crate::crypto::hash::sha256;

use super::error::{CryptoFsError, CryptoResult};
use super::types::*;

pub fn derive_key(path: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let path_bytes = path.as_bytes();
    let total_len = SALT_SIZE + path_bytes.len() + KEY_DERIVATION_CONTEXT.len();

    let mut input = Vec::with_capacity(total_len);
    input.extend_from_slice(salt);
    input.extend_from_slice(path_bytes);
    input.extend_from_slice(KEY_DERIVATION_CONTEXT);

    sha256(&input)
}

pub fn generate_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    fill_random_bytes(&mut nonce[0..4]);
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
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

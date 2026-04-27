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
use super::EncryptionError;
use crate::crypto::random_api::fill_bytes;
use crate::crypto::symmetric::chacha20poly1305::{aead_encrypt, NONCE_SIZE};
use alloc::vec::Vec;

pub fn encrypt_message(data: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    fill_bytes(&mut nonce_bytes).map_err(|_| EncryptionError::InsufficientEntropy)?;

    let ciphertext: Vec<u8> = match aead_encrypt(shared_secret, &nonce_bytes, &[], data) {
        Ok(ct) => ct,
        Err(_) => return Err(EncryptionError::EncryptionFailed),
    };

    let mut encrypted = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);

    Ok(encrypted)
}

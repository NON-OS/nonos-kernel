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
use crate::crypto::chacha20poly1305::{aead_decrypt, NONCE_SIZE, TAG_SIZE};
use super::EncryptionError;

pub fn decrypt_message(encrypted_data: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
    if encrypted_data.len() < NONCE_SIZE + TAG_SIZE {
        return Err(EncryptionError::InvalidNonceSize);
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&encrypted_data[0..NONCE_SIZE]);
    let ciphertext = &encrypted_data[NONCE_SIZE..];

    let plaintext = aead_decrypt(shared_secret, &nonce, &[], ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    Ok(plaintext)
}
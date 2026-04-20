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
use crate::crypto::chacha20poly1305::{aead_encrypt, NONCE_SIZE, TAG_SIZE};
use crate::crypto::fill_random_bytes;
use super::EncryptionError;

pub fn encrypt_message(data: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    fill_random_bytes(&mut nonce_bytes);

    let mut ciphertext = vec![0u8; data.len() + TAG_SIZE];
    let result = aead_encrypt(shared_secret, &nonce_bytes, &[], data, &mut ciphertext);

    if result != 0 {
        return Err(EncryptionError::EncryptionFailed);
    }

    let mut encrypted = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);

    Ok(encrypted)
}
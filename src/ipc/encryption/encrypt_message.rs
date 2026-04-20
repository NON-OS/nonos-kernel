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
use crate::crypto::chacha20poly1305::{ChaCha20Poly1305, Nonce};
use crate::crypto::rand::secure_random_bytes;
use super::EncryptionError;

pub fn encrypt_message(data: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
    let mut nonce_bytes = [0u8; 24];
    secure_random_bytes(&mut nonce_bytes)
        .map_err(|_| EncryptionError::InsufficientEntropy)?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(shared_secret.into());

    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    let mut encrypted = Vec::with_capacity(24 + ciphertext.len());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);

    Ok(encrypted)
}
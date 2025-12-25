// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! AES-256-CTR encryption for data-at-rest.

use spin::Mutex;
use crate::crypto::aes::Aes256;

use super::super::error::AhciError;

/// Encrypts a buffer using AES-256-CTR with a sector-specific nonce.
///
/// # Safety
///
/// Caller must ensure `buffer` points to `size` bytes of valid memory.
pub fn encrypt_buffer_aes(
    aes_cipher: &Mutex<Option<Aes256>>,
    encryption_iv: &[u8; 16],
    buffer: u64,
    size: usize,
    lba: u64,
) -> Result<(), AhciError> {
    let cipher_lock = aes_cipher.lock();
    let cipher = cipher_lock.as_ref().ok_or(AhciError::CipherNotInitialized)?;

    // SAFETY: Caller guarantees buffer points to size bytes of valid memory.
    unsafe {
        let data = core::slice::from_raw_parts_mut(buffer as *mut u8, size);

        // Create sector-specific nonce: base IV XOR with LBA
        let mut nonce_counter = *encryption_iv;
        // Mix in LBA for sector-specific encryption
        let lba_bytes = lba.to_le_bytes();
        for i in 0..8 {
            nonce_counter[i] ^= lba_bytes[i];
        }

        // Apply AES-256-CTR
        cipher.ctr_apply(&mut nonce_counter, data);
    }

    Ok(())
}

/// Decrypts a buffer using AES-256-CTR.
/// In CTR mode, decryption is identical to encryption.
#[inline]
pub fn decrypt_buffer_aes(
    aes_cipher: &Mutex<Option<Aes256>>,
    encryption_iv: &[u8; 16],
    buffer: u64,
    size: usize,
    lba: u64,
) -> Result<(), AhciError> {
    encrypt_buffer_aes(aes_cipher, encryption_iv, buffer, size, lba)
}

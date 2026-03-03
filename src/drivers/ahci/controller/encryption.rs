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


use spin::Mutex;
use crate::crypto::aes::Aes256;

use super::super::error::AhciError;

pub(super) fn encrypt_buffer_aes(
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

        let mut nonce_counter = *encryption_iv;
        let lba_bytes = lba.to_le_bytes();
        for i in 0..8 {
            nonce_counter[i] ^= lba_bytes[i];
        }

        cipher.ctr_apply(&mut nonce_counter, data);

        // SAFETY: Zero sensitive cryptographic material to prevent leakage.
        core::ptr::write_volatile(&mut nonce_counter, [0u8; 16]);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    Ok(())
}

#[inline]
pub(super) fn decrypt_buffer_aes(
    aes_cipher: &Mutex<Option<Aes256>>,
    encryption_iv: &[u8; 16],
    buffer: u64,
    size: usize,
    lba: u64,
) -> Result<(), AhciError> {
    encrypt_buffer_aes(aes_cipher, encryption_iv, buffer, size, lba)
}

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
use core::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::chacha20poly1305::{aead_encrypt, aead_decrypt};
use crate::crypto::rng::fill_random_bytes;

use super::super::error::{FsError, FsResult};
use super::super::types::{KEY_SIZE, NONCE_SIZE, TAG_SIZE, FILE_AAD, FsStatistics};

pub(crate) fn generate_nonce(nonce_counter: &AtomicU64) -> [u8; NONCE_SIZE] {
    let counter = nonce_counter.fetch_add(1, Ordering::SeqCst);
    let mut nonce = [0u8; NONCE_SIZE];
    fill_random_bytes(&mut nonce[0..4]);
    nonce[4..NONCE_SIZE].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub(crate) fn encrypt_file_data(
    data: &[u8],
    key: &[u8; KEY_SIZE],
    nonce_counter: &AtomicU64,
    stats: &spin::RwLock<FsStatistics>,
) -> FsResult<Vec<u8>> {
    let nonce = generate_nonce(nonce_counter);

    let ct_and_tag = aead_encrypt(key, &nonce, FILE_AAD, data)
        .map_err(|_| FsError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ct_and_tag.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ct_and_tag);

    {
        let mut stats = stats.write();
        stats.encryptions += 1;
    }

    Ok(result)
}

pub fn decrypt_file_data(
    encrypted: &[u8],
    key: &[u8; KEY_SIZE],
    stats: &spin::RwLock<FsStatistics>,
) -> FsResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(FsError::DataTooShort);
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&encrypted[0..NONCE_SIZE]);

    let ct_and_tag = &encrypted[NONCE_SIZE..];

    let result = aead_decrypt(key, &nonce, FILE_AAD, ct_and_tag);

    {
        let mut stats = stats.write();
        if result.is_ok() {
            stats.decryptions += 1;
        } else {
            stats.decryption_failures += 1;
        }
    }

    result.map_err(|_| FsError::DecryptionFailed)
}

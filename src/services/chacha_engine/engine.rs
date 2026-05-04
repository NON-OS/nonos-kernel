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

use crate::crypto::chacha20poly1305::{
    aead_decrypt_in_place, aead_encrypt_in_place, chacha20_block,
};
use core::sync::atomic::{AtomicU64, Ordering};

static ENCRYPT_COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES_PROCESSED: AtomicU64 = AtomicU64::new(0);

pub(super) fn encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let mut keystream = [0u8; 64];
        chacha20_block(key, nonce, counter + i as u32, &mut keystream);
        for (j, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[j];
        }
    }
    ENCRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn decrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    encrypt(key, nonce, counter, data);
}

pub(super) fn encrypt_poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &mut [u8],
    tag: &mut [u8; 16],
) {
    let len = data.len();
    let mut buffer = [0u8; 512];
    buffer[..len].copy_from_slice(data);
    if let Ok(_result_len) = aead_encrypt_in_place(key, nonce, &[], &mut buffer, len) {
        data.copy_from_slice(&buffer[..len]);
        tag.copy_from_slice(&buffer[len..len + 16]);
    }
    ENCRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn decrypt_poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let len = data.len();
    let mut buffer = [0u8; 528];
    buffer[..len].copy_from_slice(data);
    buffer[len..len + 16].copy_from_slice(tag);
    let result = aead_decrypt_in_place(key, nonce, &[], &mut buffer, len + 16).is_ok();
    if result {
        data.copy_from_slice(&buffer[..len]);
    }
    ENCRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(data.len() as u64, Ordering::Relaxed);
    result
}

pub(super) fn get_stats() -> (u64, u64) {
    (ENCRYPT_COUNT.load(Ordering::Relaxed), BYTES_PROCESSED.load(Ordering::Relaxed))
}

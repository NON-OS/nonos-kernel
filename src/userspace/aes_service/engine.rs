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

use crate::crypto::aes::Aes256;
use core::sync::atomic::{AtomicU64, Ordering};

static ENCRYPT_COUNT: AtomicU64 = AtomicU64::new(0);
static DECRYPT_COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES_PROCESSED: AtomicU64 = AtomicU64::new(0);

pub(super) fn encrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let cipher = Aes256::new(key);
    let result = cipher.encrypt_block(block);
    block.copy_from_slice(&result);
    ENCRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(16, Ordering::Relaxed);
}

pub(super) fn decrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let cipher = Aes256::new(key);
    let result = cipher.decrypt_block(block);
    block.copy_from_slice(&result);
    DECRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(16, Ordering::Relaxed);
}

pub(super) fn encrypt_ctr(key: &[u8; 32], nonce: &mut [u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new(key);
    cipher.ctr_apply(nonce, data);
    ENCRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn decrypt_ctr(key: &[u8; 32], nonce: &mut [u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new(key);
    cipher.ctr_apply(nonce, data);
    DECRYPT_COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES_PROCESSED.fetch_add(data.len() as u64, Ordering::Relaxed);
}

pub(super) fn get_stats() -> (u64, u64, u64) {
    (
        ENCRYPT_COUNT.load(Ordering::Relaxed),
        DECRYPT_COUNT.load(Ordering::Relaxed),
        BYTES_PROCESSED.load(Ordering::Relaxed),
    )
}

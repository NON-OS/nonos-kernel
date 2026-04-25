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

use super::types::MemEncryptStats;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static MASTER_KEY: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
static KEY_COUNTER: AtomicU64 = AtomicU64::new(1);
pub(super) static STATS: MemEncryptStats = MemEncryptStats {
    regions_protected: AtomicU64::new(0),
    bytes_encrypted: AtomicU64::new(0),
    encryptions: AtomicU64::new(0),
    decryptions: AtomicU64::new(0),
    key_rotations: AtomicU64::new(0),
    auth_failures: AtomicU64::new(0),
};

pub fn init() {
    let mut key = MASTER_KEY.lock();
    crate::security::crypto::random::fill_random_bytes(&mut *key);
    INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

pub(super) fn derive_region_key(key_id: u64) -> [u8; 32] {
    let master = MASTER_KEY.lock();
    let mut info = [0u8; 24];
    info[..8].copy_from_slice(b"MEMENC01");
    info[8..16].copy_from_slice(&key_id.to_le_bytes());
    info[16..24].copy_from_slice(&crate::time::timestamp_millis().to_le_bytes());
    crate::crypto::hmac::hmac_sha256(&*master, &info)
}

pub(super) fn generate_key_id() -> u64 {
    KEY_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub(super) fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    crate::security::crypto::random::fill_random_bytes(&mut nonce);
    nonce
}

pub(super) fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    crate::crypto::aes::aes_gcm_encrypt_in_place(key, nonce, &[], data, &mut tag);
    STATS.encryptions.fetch_add(1, Ordering::Relaxed);
    STATS.bytes_encrypted.fetch_add(data.len() as u64, Ordering::Relaxed);
    tag
}

pub(super) fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let result = crate::crypto::aes::aes_gcm_decrypt_in_place(key, nonce, &[], data, tag);
    STATS.decryptions.fetch_add(1, Ordering::Relaxed);
    if !result {
        STATS.auth_failures.fetch_add(1, Ordering::Relaxed);
    }
    result
}

pub(super) fn rotate_master_key() {
    let mut key = MASTER_KEY.lock();
    let old_key = *key;
    crate::security::crypto::random::fill_random_bytes(&mut *key);
    crate::security::hardening::memory_sanitization::secure_zero_slice(&mut old_key.clone());
    STATS.key_rotations.fetch_add(1, Ordering::Relaxed);
}

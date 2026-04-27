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

use crate::crypto::aes256_gcm_decrypt as gcm_dec;
use crate::crypto::aes256_gcm_encrypt as gcm_enc;
use alloc::vec::Vec;

pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    gcm_enc(key, nonce, plaintext, aad).ok()
}

pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    gcm_dec(key, nonce, ciphertext, aad).ok()
}

pub fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let hash = crate::crypto::hash::blake3_keyed_hash(key, data);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&hash[..16]);
    mac
}

pub fn verify_mac(key: &[u8; 32], data: &[u8], expected: &[u8; 16]) -> bool {
    let computed = compute_mac(key, data);
    crate::crypto::util::constant_time::ct_eq(&computed, expected)
}

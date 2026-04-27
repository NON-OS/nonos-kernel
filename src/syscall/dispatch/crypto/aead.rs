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

use crate::capabilities::Capability;
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

pub fn handle_crypto_encrypt(
    algo: u64,
    key_ptr: u64,
    nonce_ptr: u64,
    plaintext_ptr: u64,
    plaintext_len: u64,
    ciphertext_ptr: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    if key_ptr == 0 || nonce_ptr == 0 || plaintext_ptr == 0 || ciphertext_ptr == 0 {
        return errno(22);
    }
    if plaintext_len == 0 || plaintext_len > 1024 * 1024 {
        return errno(22);
    }
    let mut key_arr = [0u8; 32];
    let mut nonce_arr = [0u8; 12];
    let mut plaintext = alloc::vec![0u8; plaintext_len as usize];
    if copy_from_user(key_ptr, &mut key_arr).is_err() {
        return errno(14);
    }
    if copy_from_user(nonce_ptr, &mut nonce_arr).is_err() {
        return errno(14);
    }
    if copy_from_user(plaintext_ptr, &mut plaintext).is_err() {
        return errno(14);
    }
    let result = match algo {
        0 => crate::crypto::chacha20poly1305_encrypt(&key_arr, &nonce_arr, &plaintext, &[]),
        1 => crate::crypto::aes256_gcm_encrypt(&key_arr, &nonce_arr, &plaintext, &[]),
        _ => return errno(22),
    };
    match result {
        Ok(ct) => {
            if copy_to_user(ciphertext_ptr, &ct).is_err() {
                return errno(14);
            }
            SyscallResult {
                value: ct.len() as i64,
                capability_consumed: false,
                audit_required: true,
            }
        }
        Err(_) => errno(5),
    }
}

pub fn handle_crypto_decrypt(
    algo: u64,
    key_ptr: u64,
    nonce_ptr: u64,
    ciphertext_ptr: u64,
    ciphertext_len: u64,
    plaintext_ptr: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    if key_ptr == 0 || nonce_ptr == 0 || ciphertext_ptr == 0 || plaintext_ptr == 0 {
        return errno(22);
    }
    if ciphertext_len < 16 || ciphertext_len > 1024 * 1024 + 16 {
        return errno(22);
    }
    let mut key_arr = [0u8; 32];
    let mut nonce_arr = [0u8; 12];
    let mut ciphertext = alloc::vec![0u8; ciphertext_len as usize];
    if copy_from_user(key_ptr, &mut key_arr).is_err() {
        return errno(14);
    }
    if copy_from_user(nonce_ptr, &mut nonce_arr).is_err() {
        return errno(14);
    }
    if copy_from_user(ciphertext_ptr, &mut ciphertext).is_err() {
        return errno(14);
    }
    let result = match algo {
        0 => crate::crypto::chacha20poly1305_decrypt(&key_arr, &nonce_arr, &ciphertext, &[]),
        1 => crate::crypto::aes256_gcm_decrypt(&key_arr, &nonce_arr, &ciphertext, &[]),
        _ => return errno(22),
    };
    match result {
        Ok(pt) => {
            if copy_to_user(plaintext_ptr, &pt).is_err() {
                return errno(14);
            }
            SyscallResult {
                value: pt.len() as i64,
                capability_consumed: false,
                audit_required: true,
            }
        }
        Err(_) => errno(74),
    }
}

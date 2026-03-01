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

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::{errno, require_capability};

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

    let key = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, 32) };
    let nonce = unsafe { core::slice::from_raw_parts(nonce_ptr as *const u8, 12) };
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext_ptr as *const u8, plaintext_len as usize) };
    let ciphertext = unsafe { core::slice::from_raw_parts_mut(ciphertext_ptr as *mut u8, plaintext_len as usize + 16) };

    let mut key_arr = [0u8; 32];
    let mut nonce_arr = [0u8; 12];
    key_arr.copy_from_slice(key);
    nonce_arr.copy_from_slice(nonce);

    match algo {
        0 => {
            match crate::crypto::chacha20poly1305_encrypt(&key_arr, &nonce_arr, plaintext, &[]) {
                Ok(ct) => {
                    if ct.len() <= ciphertext.len() {
                        ciphertext[..ct.len()].copy_from_slice(&ct);
                        SyscallResult { value: ct.len() as i64, capability_consumed: false, audit_required: true }
                    } else {
                        errno(34)
                    }
                }
                Err(_) => errno(5),
            }
        }
        1 => {
            match crate::crypto::aes256_gcm_encrypt(&key_arr, &nonce_arr, plaintext, &[]) {
                Ok(ct) => {
                    if ct.len() <= ciphertext.len() {
                        ciphertext[..ct.len()].copy_from_slice(&ct);
                        SyscallResult { value: ct.len() as i64, capability_consumed: false, audit_required: true }
                    } else {
                        errno(34)
                    }
                }
                Err(_) => errno(5),
            }
        }
        _ => errno(22),
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

    let key = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, 32) };
    let nonce = unsafe { core::slice::from_raw_parts(nonce_ptr as *const u8, 12) };
    let ciphertext = unsafe { core::slice::from_raw_parts(ciphertext_ptr as *const u8, ciphertext_len as usize) };
    let plaintext = unsafe { core::slice::from_raw_parts_mut(plaintext_ptr as *mut u8, ciphertext_len as usize - 16) };

    let mut key_arr = [0u8; 32];
    let mut nonce_arr = [0u8; 12];
    key_arr.copy_from_slice(key);
    nonce_arr.copy_from_slice(nonce);

    match algo {
        0 => {
            match crate::crypto::chacha20poly1305_decrypt(&key_arr, &nonce_arr, ciphertext, &[]) {
                Ok(pt) => {
                    if pt.len() <= plaintext.len() {
                        plaintext[..pt.len()].copy_from_slice(&pt);
                        SyscallResult { value: pt.len() as i64, capability_consumed: false, audit_required: true }
                    } else {
                        errno(34)
                    }
                }
                Err(_) => errno(74),
            }
        }
        1 => {
            match crate::crypto::aes256_gcm_decrypt(&key_arr, &nonce_arr, ciphertext, &[]) {
                Ok(pt) => {
                    if pt.len() <= plaintext.len() {
                        plaintext[..pt.len()].copy_from_slice(&pt);
                        SyscallResult { value: pt.len() as i64, capability_consumed: false, audit_required: true }
                    } else {
                        errno(34)
                    }
                }
                Err(_) => errno(74),
            }
        }
        _ => errno(22),
    }
}

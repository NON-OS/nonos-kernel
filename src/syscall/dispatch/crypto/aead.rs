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
use crate::security::crypto_capsule::client as crypto_client;
use crate::security::crypto_capsule::CryptoCapsuleError;
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

const ALGO_CHACHA20_POLY1305: u64 = 0;
const ALGO_AES256_GCM: u64 = 1;

const MAX_AEAD_PT: usize = 1024 * 1024;
const TAG_LEN: usize = 16;

// User-facing CryptoEncrypt. CAP_CRYPTO at the gate; raw key/nonce
// usercopied in; bytes routed to capsule_crypto over IPC; the kernel
// owns no AEAD authority.
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
    if plaintext_len == 0 || plaintext_len as usize > MAX_AEAD_PT {
        return errno(22);
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut plaintext = alloc::vec![0u8; plaintext_len as usize];
    if copy_from_user(key_ptr, &mut key).is_err()
        || copy_from_user(nonce_ptr, &mut nonce).is_err()
        || copy_from_user(plaintext_ptr, &mut plaintext).is_err()
    {
        return errno(14);
    }
    let result = match algo {
        ALGO_CHACHA20_POLY1305 => crypto_client::chacha20_poly1305_seal(&key, &nonce, &[], &plaintext),
        ALGO_AES256_GCM => crypto_client::aes256_gcm_seal(&key, &nonce, &[], &plaintext),
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
        Err(e) => map_capsule_error(e),
    }
}

// User-facing CryptoDecrypt. Same shape as encrypt; tag-verify
// failure surfaces as EBADMSG (-74).
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
    if (ciphertext_len as usize) < TAG_LEN
        || ciphertext_len as usize > MAX_AEAD_PT + TAG_LEN
    {
        return errno(22);
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut ciphertext = alloc::vec![0u8; ciphertext_len as usize];
    if copy_from_user(key_ptr, &mut key).is_err()
        || copy_from_user(nonce_ptr, &mut nonce).is_err()
        || copy_from_user(ciphertext_ptr, &mut ciphertext).is_err()
    {
        return errno(14);
    }
    let result = match algo {
        ALGO_CHACHA20_POLY1305 => crypto_client::chacha20_poly1305_open(&key, &nonce, &[], &ciphertext),
        ALGO_AES256_GCM => crypto_client::aes256_gcm_open(&key, &nonce, &[], &ciphertext),
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
        Err(e) => map_capsule_error(e),
    }
}

fn map_capsule_error(err: CryptoCapsuleError) -> SyscallResult {
    match err {
        CryptoCapsuleError::AccessDenied => errno(13),
        CryptoCapsuleError::InvalidArgument => errno(22),
        CryptoCapsuleError::AuthFailure => errno(74),
        CryptoCapsuleError::OversizedRequest => errno(90),
        CryptoCapsuleError::ProtocolMismatch => errno(71),
        CryptoCapsuleError::Dead => errno(19),
        CryptoCapsuleError::Stale => errno(116),
        CryptoCapsuleError::NoCallerPid | CryptoCapsuleError::TransportFailure => errno(5),
    }
}

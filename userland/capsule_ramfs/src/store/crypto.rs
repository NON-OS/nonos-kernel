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

use nonos_libc::{crypto_decrypt, crypto_encrypt, crypto_random};

use super::types::StoreError;

pub(super) const ALGO_CHACHA20_POLY1305: u64 = 0;
pub(super) const KEY_LEN: usize = 32;
pub(super) const NONCE_LEN: usize = 12;
pub(super) const TAG_LEN: usize = 16;

pub(super) fn fresh_key() -> Result<[u8; KEY_LEN], StoreError> {
    let mut k = [0u8; KEY_LEN];
    if crypto_random(k.as_mut_ptr(), KEY_LEN) < 0 {
        return Err(StoreError::CryptoFailure);
    }
    Ok(k)
}

pub(super) fn fresh_nonce() -> Result<[u8; NONCE_LEN], StoreError> {
    let mut n = [0u8; NONCE_LEN];
    if crypto_random(n.as_mut_ptr(), NONCE_LEN) < 0 {
        return Err(StoreError::CryptoFailure);
    }
    Ok(n)
}

pub(super) fn seal(
    key: &[u8],
    nonce: &[u8],
    plain: &[u8],
    cipher: &mut [u8],
) -> Result<usize, StoreError> {
    let n = crypto_encrypt(
        ALGO_CHACHA20_POLY1305,
        key.as_ptr(),
        nonce.as_ptr(),
        plain.as_ptr(),
        plain.len() as u64,
        cipher.as_mut_ptr(),
    );
    if n < 0 {
        return Err(StoreError::CryptoFailure);
    }
    Ok(n as usize)
}

pub(super) fn open(
    key: &[u8],
    nonce: &[u8],
    cipher: &[u8],
    plain: &mut [u8],
) -> Result<usize, StoreError> {
    let n = crypto_decrypt(
        ALGO_CHACHA20_POLY1305,
        key.as_ptr(),
        nonce.as_ptr(),
        cipher.as_ptr(),
        cipher.len() as u64,
        plain.as_mut_ptr(),
    );
    if n < 0 {
        return Err(StoreError::CryptoFailure);
    }
    Ok(n as usize)
}

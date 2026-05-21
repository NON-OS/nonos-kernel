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

use nonos_libc::{crypto_decrypt, crypto_encrypt};

use super::types::{CryptoError, Key, Nonce, TAG_BYTES};

const ALGO_CHACHA20_POLY1305: u64 = 0;

pub fn seal(
    key: &Key,
    nonce: &Nonce,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    if out.len() < plaintext.len() + TAG_BYTES {
        return Err(CryptoError::OutputSmall);
    }
    let n = crypto_encrypt(
        ALGO_CHACHA20_POLY1305,
        key.as_ptr(),
        nonce.as_ptr(),
        plaintext.as_ptr(),
        plaintext.len() as u64,
        out.as_mut_ptr(),
    );
    if n >= 0 {
        Ok(n as usize)
    } else {
        Err(CryptoError::Seal)
    }
}

pub fn open(
    key: &Key,
    nonce: &Nonce,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    if ciphertext.len() < TAG_BYTES || out.len() + TAG_BYTES < ciphertext.len() {
        return Err(CryptoError::OutputSmall);
    }
    let n = crypto_decrypt(
        ALGO_CHACHA20_POLY1305,
        key.as_ptr(),
        nonce.as_ptr(),
        ciphertext.as_ptr(),
        ciphertext.len() as u64,
        out.as_mut_ptr(),
    );
    if n >= 0 {
        Ok(n as usize)
    } else {
        Err(CryptoError::Open)
    }
}

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

use alloc::vec::Vec;

use super::super::error::CryptoCapsuleError;
use super::super::protocol::{OP_AES256_GCM_OPEN, OP_AES256_GCM_SEAL};
use super::aead_op;

pub fn aes256_gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoCapsuleError> {
    aead_op::seal(OP_AES256_GCM_SEAL, key, nonce, aad, plaintext)
}

pub fn aes256_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoCapsuleError> {
    aead_op::open(OP_AES256_GCM_OPEN, key, nonce, aad, ciphertext)
}

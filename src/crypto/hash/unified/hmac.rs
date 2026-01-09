// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use crate::crypto::constant_time;
use super::{Hash256, sha256};

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Hash256 {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hk = sha256(key);
        key_block[..32].copy_from_slice(&hk);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    constant_time::secure_zero(&mut key_block);

    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    constant_time::secure_zero(&mut ipad);

    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    let result = sha256(&outer);

    constant_time::secure_zero(&mut opad);

    result
}

pub fn hmac_verify(key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    let expect = hmac_sha256(key, message);
    constant_time::ct_eq(&expect, mac)
}

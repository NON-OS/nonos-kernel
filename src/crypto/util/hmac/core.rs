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
use alloc::vec::Vec;
use crate::crypto::hash::{sha256, Hash256};
use crate::crypto::sha512::{sha512, Hash512};

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Hash256 {
    hmac_generic(key, message, 64, sha256)
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Hash512 {
    hmac_generic(key, message, 128, sha512)
}

fn hmac_generic<F, H>(key: &[u8], message: &[u8], block_size: usize, hash_fn: F) -> H
where
    F: Fn(&[u8]) -> H,
    H: AsRef<[u8]> + Clone,
{
    let mut padded_key = alloc::vec![0u8; block_size];

    if key.len() > block_size {
        let hashed_key = hash_fn(key);
        let hashed_bytes = hashed_key.as_ref();
        padded_key[..hashed_bytes.len()].copy_from_slice(hashed_bytes);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = alloc::vec![0x36u8; block_size];
    let mut outer_pad = alloc::vec![0x5cu8; block_size];

    for i in 0..block_size {
        inner_pad[i] ^= padded_key[i];
        outer_pad[i] ^= padded_key[i];
    }

    for b in padded_key.iter_mut() {
        // SAFETY: Volatile write prevents compiler optimization of zeroization.
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    let mut inner_message = Vec::with_capacity(block_size + message.len());
    inner_message.extend_from_slice(&inner_pad);
    inner_message.extend_from_slice(message);
    let inner_hash = hash_fn(&inner_message);

    for b in inner_pad.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    let mut outer_message = Vec::with_capacity(block_size + inner_hash.as_ref().len());
    outer_message.extend_from_slice(&outer_pad);
    outer_message.extend_from_slice(inner_hash.as_ref());
    let result = hash_fn(&outer_message);

    for b in outer_pad.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    result
}

pub fn hmac_verify(mac1: &[u8], mac2: &[u8]) -> bool {
    if mac1.len() != mac2.len() {
        return false;
    }

    let mut result = 0u8;
    for (a, b) in mac1.iter().zip(mac2.iter()) {
        result |= a ^ b;
    }

    result == 0
}

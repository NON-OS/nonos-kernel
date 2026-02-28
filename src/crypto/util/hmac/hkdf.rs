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
use crate::crypto::hash::Hash256;
use super::core::hmac_sha256;

pub fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> Hash256 {
    hmac_sha256(salt, input_key_material)
}

pub fn hkdf_expand(prk: &Hash256, info: &[u8], length: usize) -> Result<Vec<u8>, &'static str> {
    let hash_len = 32;
    let n = (length + hash_len - 1) / hash_len;

    if n > 255 {
        return Err("HKDF expand: requested length too large (max 8160 bytes)");
    }

    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut hmac_input = Vec::with_capacity(t.len() + info.len() + 1);
        hmac_input.extend_from_slice(&t);
        hmac_input.extend_from_slice(info);
        hmac_input.push(i as u8);

        t = hmac_sha256(prk, &hmac_input).to_vec();
        output.extend_from_slice(&t);

        for b in hmac_input.iter_mut() {
            // SAFETY: Volatile write prevents compiler optimization of zeroization.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }

    for b in t.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    output.truncate(length);
    Ok(output)
}

pub fn hkdf(salt: &[u8], input_key_material: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, &'static str> {
    let prk = hkdf_extract(salt, input_key_material);
    hkdf_expand(&prk, info, length)
}

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

use crate::crypto::hash::{hmac_sha256, sha256};
use alloc::vec::Vec;

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, out_len)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt_key = if salt.is_empty() {
        [0u8; 32]
    } else {
        let mut k = [0u8; 32];
        let h = sha256(salt);
        k.copy_from_slice(&h);
        k
    };
    hmac_sha256(&salt_key, ikm)
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(out_len);
    let mut t = Vec::new();
    let mut counter = 1u8;
    while output.len() < out_len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        let block = hmac_sha256(prk, &input);
        t = block.to_vec();
        output.extend_from_slice(&block);
        counter = counter.saturating_add(1);
    }
    output.truncate(out_len);
    output
}

pub fn derive_key(shared_secret: &[u8], label: &[u8]) -> [u8; 32] {
    let expanded = hkdf_sha256(shared_secret, b"nym-sphinx", label, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&expanded);
    key
}

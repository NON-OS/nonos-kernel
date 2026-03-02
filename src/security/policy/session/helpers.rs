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

use alloc::{string::String, vec::Vec, format};
use super::types::HASH_ITERATIONS;
use crate::crypto::hash::sha256;

pub fn derive_password_hash(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(salt.len() + password.len());
    data.extend_from_slice(salt);
    data.extend_from_slice(password);
    let mut result = sha256(&data);

    for _ in 0..HASH_ITERATIONS {
        let mut iter_data = Vec::with_capacity(32 + salt.len());
        iter_data.extend_from_slice(&result);
        iter_data.extend_from_slice(salt);
        result = sha256(&iter_data);
    }

    result
}

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => { components.pop(); }
            p => components.push(p),
        }
    }

    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

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

use super::hasher::Hasher;
use super::{KEY_LEN, OUT_LEN};

pub fn blake3_hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

pub fn blake3_hash_xof(input: &[u8], output: &mut [u8]) {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize_xof().fill(output);
}

pub fn blake3_keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(input);
    hasher.finalize()
}

pub fn blake3_derive_key(context: &str, key_material: &[u8], output: &mut [u8]) {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(key_material);
    hasher.finalize_xof().fill(output);
}

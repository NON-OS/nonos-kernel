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

use crate::crypto::util::rng;

pub fn secure_random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    rng::fill_random_bytes(&mut bytes);
    u32::from_le_bytes(bytes)
}

pub fn secure_random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    rng::fill_random_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub fn secure_random_u8() -> u8 {
    let mut bytes = [0u8; 1];
    rng::fill_random_bytes(&mut bytes);
    bytes[0]
}

pub fn fill_random(buf: &mut [u8]) {
    rng::fill_random_bytes(buf);
}

pub fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rng::fill_random_bytes(&mut key);
    key
}

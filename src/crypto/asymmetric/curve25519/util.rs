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

use super::field::FieldElement;
use super::x25519::x25519_base;

pub(crate) const SQRT_M1: FieldElement = FieldElement([
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d,
]);

#[inline]
pub fn scalarmult_base(secret: &[u8; 32]) -> [u8; 32] {
    x25519_base(secret)
}

pub(crate) fn load_u64_le(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        v |= (b as u64) << (8 * i);
    }
    v
}

pub(crate) fn store_u64_le(bytes: &mut [u8], v: u64) {
    for (i, b) in bytes.iter_mut().take(8).enumerate() {
        *b = (v >> (8 * i)) as u8;
    }
}

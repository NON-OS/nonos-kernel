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

pub(crate) fn mgf1(seed: &[u8], mask_len: usize) -> Vec<u8> {
    use crate::crypto::hash::sha256;

    let mut mask = Vec::with_capacity(mask_len);
    let mut counter = 0u32;

    while mask.len() < mask_len {
        let mut hasher_input = seed.to_vec();
        hasher_input.extend_from_slice(&counter.to_be_bytes());
        let hash = sha256(&hasher_input);
        mask.extend_from_slice(&hash);
        counter += 1;
    }

    mask.truncate(mask_len);
    mask
}

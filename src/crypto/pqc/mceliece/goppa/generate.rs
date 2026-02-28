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

use alloc::vec;
use alloc::vec::Vec;
use crate::crypto::rng;
use super::super::{MCELIECE_N, MCELIECE_T, MCELIECE_M, FIELD_SIZE};
use super::poly::is_likely_irreducible;

pub(crate) fn generate_goppa_polynomial() -> Vec<u16> {
    loop {
        let mut poly = vec![0u16; MCELIECE_T + 1];

        for coeff in &mut poly[..MCELIECE_T] {
            let r = rng::random_u32();
            *coeff = (r as u16) & ((1 << MCELIECE_M) - 1);
        }
        poly[MCELIECE_T] = 1;

        if is_likely_irreducible(&poly) {
            return poly;
        }
    }
}

pub(crate) fn generate_support() -> Vec<u16> {
    let mut support: Vec<u16> = (0..FIELD_SIZE as u16).collect();

    for i in (1..FIELD_SIZE).rev() {
        let j = rng::random_range((i + 1) as u32) as usize;
        support.swap(i, j);
    }

    support.truncate(MCELIECE_N);
    support
}

pub(crate) fn generate_permutation() -> Vec<u16> {
    let mut perm: Vec<u16> = (0..MCELIECE_N as u16).collect();

    for i in (1..MCELIECE_N).rev() {
        let j = rng::random_range((i + 1) as u32) as usize;
        perm.swap(i, j);
    }

    perm
}

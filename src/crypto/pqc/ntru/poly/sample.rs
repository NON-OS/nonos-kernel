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
use crate::crypto::rng;
use super::super::NTRU_N;
use super::types::Polynomial;

pub(crate) fn sample_ternary(num_ones: usize, num_neg_ones: usize) -> Polynomial {
    let mut p = Polynomial::new();
    let mut positions: Vec<usize> = (0..NTRU_N).collect();

    for i in (1..NTRU_N).rev() {
        let j = rng::random_range((i + 1) as u32) as usize;
        positions.swap(i, j);
    }

    for i in 0..num_ones {
        p.coeffs[positions[i]] = 1;
    }

    for i in num_ones..(num_ones + num_neg_ones) {
        p.coeffs[positions[i]] = -1;
    }

    p
}

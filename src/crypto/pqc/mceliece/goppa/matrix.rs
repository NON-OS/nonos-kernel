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
use super::super::gf::GF2m;
use super::super::{MCELIECE_N, MCELIECE_K, MCELIECE_T, MCELIECE_M};
use super::poly::poly_eval;

pub(crate) fn compute_parity_check_matrix(goppa: &[u16], support: &[u16]) -> Vec<Vec<u8>> {
    let r = MCELIECE_N - MCELIECE_K;

    let mut h = vec![vec![0u8; MCELIECE_N]; r];

    for j in 0..MCELIECE_N {
        let alpha = support[j];
        let g_alpha = poly_eval(goppa, alpha);

        if g_alpha == 0 {
            continue;
        }

        let g_alpha_inv = GF2m::inv(g_alpha);

        let mut val = g_alpha_inv;
        for i in 0..MCELIECE_T {
            for b in 0..MCELIECE_M {
                let row = i * MCELIECE_M + b;
                if row < r {
                    h[row][j] = ((val >> b) & 1) as u8;
                }
            }
            val = GF2m::mul(val, alpha);
        }
    }

    h
}

pub(crate) fn to_systematic_form(h: &[Vec<u8>]) -> Option<Vec<u8>> {
    let r = MCELIECE_N - MCELIECE_K;
    let mut matrix = h.to_vec();

    for i in 0..r {
        let mut pivot = None;
        for j in i..MCELIECE_N {
            if matrix[i][j] == 1 {
                pivot = Some(j);
                break;
            }
        }

        let pivot_col = pivot?;

        if pivot_col != i {
            for row in &mut matrix {
                row.swap(i, pivot_col);
            }
        }

        for j in 0..r {
            if j != i && matrix[j][i] == 1 {
                for k in 0..MCELIECE_N {
                    matrix[j][k] ^= matrix[i][k];
                }
            }
        }
    }

    let mut t_matrix = Vec::with_capacity(r * MCELIECE_K / 8);

    for row in 0..r {
        let mut byte = 0u8;
        let mut bit_pos = 0;

        for col in r..MCELIECE_N {
            byte |= matrix[row][col] << bit_pos;
            bit_pos += 1;

            if bit_pos == 8 {
                t_matrix.push(byte);
                byte = 0;
                bit_pos = 0;
            }
        }

        if bit_pos > 0 {
            t_matrix.push(byte);
        }
    }

    Some(t_matrix)
}

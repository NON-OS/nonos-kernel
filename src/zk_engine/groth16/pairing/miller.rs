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

use super::frobenius::{frobenius_map, frobenius_map_neg};
use super::line::{line_add, line_double};
use super::line_eval::mul_by_line_evaluation;
use super::BN254_X;
use crate::zk_engine::groth16::g1::G1Affine;
use crate::zk_engine::groth16::g2::G2Affine;
use crate::zk_engine::groth16::gt::GTElement;

pub(super) fn miller_loop(p: &G1Affine, q: &G2Affine) -> GTElement {
    let mut f = GTElement::one();
    let mut r = q.clone();

    let miller_bits = get_miller_loop_bits();

    for &bit in miller_bits.iter().skip(1) {
        let line = line_double(&mut r, p);
        f = f.square();
        f = mul_by_line_evaluation(&f, &line);

        if bit {
            let line = line_add(&mut r, q, p);
            f = mul_by_line_evaluation(&f, &line);
        }
    }

    let q1 = frobenius_map(q);
    let line = line_add(&mut r, &q1, p);
    f = mul_by_line_evaluation(&f, &line);

    let q2 = frobenius_map_neg(&q1);
    let line = line_add(&mut r, &q2, p);
    f = mul_by_line_evaluation(&f, &line);

    f
}

fn get_miller_loop_bits() -> [bool; 64] {
    let mut bits = [false; 64];
    let mut x = BN254_X;
    for i in 0..64 {
        bits[63 - i] = (x & 1) == 1;
        x >>= 1;
    }
    bits
}

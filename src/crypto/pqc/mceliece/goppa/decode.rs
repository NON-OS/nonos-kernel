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
use super::super::MCELIECE_N;
use super::poly::poly_eval;

pub(crate) fn berlekamp_massey(syndrome: &[u16]) -> Vec<u16> {
    let n = syndrome.len();
    let mut c = vec![0u16; n + 1];
    let mut b = vec![0u16; n + 1];
    c[0] = 1;
    b[0] = 1;

    let mut l = 0usize;
    let mut m = 1i32;
    let mut bb = 1u16;

    for i in 0..n {
        let mut d = syndrome[i];
        for j in 1..=l {
            if j < c.len() && i >= j {
                d = GF2m::add(d, GF2m::mul(c[j], syndrome[i - j]));
            }
        }

        if d == 0 {
            m += 1;
        } else if 2 * l <= i {
            let t = c.clone();
            let d_bb_inv = GF2m::mul(d, GF2m::inv(bb));
            for j in 0..b.len() {
                let shift = j as i32 + m;
                if shift >= 0 && (shift as usize) < c.len() {
                    c[shift as usize] = GF2m::add(c[shift as usize], GF2m::mul(d_bb_inv, b[j]));
                }
            }
            l = i + 1 - l;
            b = t;
            bb = d;
            m = 1;
        } else {
            let d_bb_inv = GF2m::mul(d, GF2m::inv(bb));
            for j in 0..b.len() {
                let shift = j as i32 + m;
                if shift >= 0 && (shift as usize) < c.len() {
                    c[shift as usize] = GF2m::add(c[shift as usize], GF2m::mul(d_bb_inv, b[j]));
                }
            }
            m += 1;
        }
    }

    c.truncate(l + 1);
    c
}

pub(crate) fn chien_search(locator: &[u16], support: &[u16]) -> Vec<usize> {
    let mut error_positions = Vec::new();

    for i in 0..MCELIECE_N {
        let alpha = support[i];
        let val = poly_eval(locator, alpha);
        if val == 0 {
            error_positions.push(i);
        }
    }

    error_positions
}

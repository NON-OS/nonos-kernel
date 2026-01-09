// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use super::gf::GF2m;
use super::{MCELIECE_N, MCELIECE_K, MCELIECE_T, MCELIECE_M, FIELD_SIZE};

pub fn poly_eval(coeffs: &[u16], x: u16) -> u16 {
    let mut result = 0u16;
    let mut power = 1u16;
    for &coeff in coeffs {
        result = GF2m::add(result, GF2m::mul(coeff, power));
        power = GF2m::mul(power, x);
    }

    result
}

pub fn generate_goppa_polynomial() -> Vec<u16> {
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

fn is_likely_irreducible(poly: &[u16]) -> bool {
    for x in 1..FIELD_SIZE as u16 {
        if poly_eval(poly, x) == 0 {
            return false;
        }
    }
    true
}

pub fn generate_support() -> Vec<u16> {
    let mut support: Vec<u16> = (0..FIELD_SIZE as u16).collect();
    for i in (1..FIELD_SIZE).rev() {
        let j = rng::random_range((i + 1) as u32) as usize;
        support.swap(i, j);
    }

    support.truncate(MCELIECE_N);
    support
}

pub fn generate_permutation() -> Vec<u16> {
    let mut perm: Vec<u16> = (0..MCELIECE_N as u16).collect();
    for i in (1..MCELIECE_N).rev() {
        let j = rng::random_range((i + 1) as u32) as usize;
        perm.swap(i, j);
    }

    perm
}

pub fn compute_parity_check_matrix(goppa: &[u16], support: &[u16]) -> Vec<Vec<u8>> {
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

pub fn to_systematic_form(h: &[Vec<u8>]) -> Option<Vec<u8>> {
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

pub fn poly_degree(p: &[u16]) -> usize {
    for i in (0..p.len()).rev() {
        if p[i] != 0 {
            return i;
        }
    }
    usize::MAX
}

#[allow(dead_code)]
pub fn poly_gcd(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut u = a.to_vec();
    let mut v = b.to_vec();

    while !v.iter().all(|&x| x == 0) {
        let u_deg = poly_degree(&u);
        let v_deg = poly_degree(&v);

        if u_deg < v_deg {
            core::mem::swap(&mut u, &mut v);
            continue;
        }

        if v_deg == usize::MAX {
            break;
        }

        let lead_v = v[v_deg];
        let lead_v_inv = GF2m::inv(lead_v);

        let shift = u_deg - v_deg;
        let coeff = GF2m::mul(u[u_deg], lead_v_inv);

        for i in 0..=v_deg {
            if i + shift < u.len() {
                u[i + shift] = GF2m::add(u[i + shift], GF2m::mul(v[i], coeff));
            }
        }
    }

    u
}

pub fn berlekamp_massey(syndrome: &[u16]) -> Vec<u16> {
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

pub fn chien_search(locator: &[u16], support: &[u16]) -> Vec<usize> {
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

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
use super::{NTRU_N, NTRU_Q, NTRU_LOG_Q, NTRU_WEIGHT};

#[derive(Clone)]
pub struct Polynomial {
    pub coeffs: Vec<i16>,
}

impl Polynomial {
    pub fn new() -> Self {
        Self { coeffs: vec![0i16; NTRU_N] }
    }

    pub fn from_coeffs(coeffs: Vec<i16>) -> Self {
        let mut p = Self::new();
        for (i, &c) in coeffs.iter().enumerate() {
            if i < NTRU_N {
                p.coeffs[i] = c;
            }
        }
        p
    }

    pub fn reduce_mod_q(&mut self) {
        let q = NTRU_Q as i16;
        let half_q = q / 2;
        for c in &mut self.coeffs {
            *c = *c % q;
            if *c > half_q {
                *c -= q;
            } else if *c < -half_q {
                *c += q;
            }
        }
    }

    pub fn reduce_mod_3(&mut self) {
        for c in &mut self.coeffs {
            *c = *c % 3;
            if *c > 1 {
                *c -= 3;
            } else if *c < -1 {
                *c += 3;
            }
        }
    }

    // SECURITY: Constant-time polynomial multiplication to prevent timing attacks.
    // All iterations are performed regardless of coefficient values.
    pub fn multiply(&self, other: &Polynomial) -> Polynomial {
        let mut result = Polynomial::new();

        for i in 0..NTRU_N {
            for j in 0..NTRU_N {
                let k = (i + j) % NTRU_N;
                result.coeffs[k] = result.coeffs[k].wrapping_add(
                    self.coeffs[i].wrapping_mul(other.coeffs[j])
                );
            }
        }

        result
    }

    pub fn add(&self, other: &Polynomial) -> Polynomial {
        let mut result = Polynomial::new();
        for i in 0..NTRU_N {
            result.coeffs[i] = self.coeffs[i].wrapping_add(other.coeffs[i]);
        }
        result
    }

    pub fn sub(&self, other: &Polynomial) -> Polynomial {
        let mut result = Polynomial::new();
        for i in 0..NTRU_N {
            result.coeffs[i] = self.coeffs[i].wrapping_sub(other.coeffs[i]);
        }
        result
    }

    pub fn scale(&self, s: i16) -> Polynomial {
        let mut result = Polynomial::new();
        for i in 0..NTRU_N {
            result.coeffs[i] = self.coeffs[i].wrapping_mul(s);
        }
        result
    }
}

pub fn sample_ternary(num_ones: usize, num_neg_ones: usize) -> Polynomial {
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

pub fn sample_uniform_q() -> Polynomial {
    let mut p = Polynomial::new();
    let half_q = (NTRU_Q / 2) as i16;

    for c in &mut p.coeffs {
        let r = (rng::random_u32() as u16) % NTRU_Q;
        *c = r as i16 - half_q;
    }

    p
}

fn poly_deg(p: &[i16]) -> usize {
    for i in (0..p.len()).rev() {
        if p[i] != 0 {
            return i;
        }
    }
    0
}

fn mod_inv_3(a: i16) -> i16 {
    let a = ((a % 3) + 3) % 3;
    match a {
        1 => 1,
        2 => 2,
        _ => 0,
    }
}

pub fn poly_inverse_mod_3(f: &Polynomial) -> Option<Polynomial> {
    let mut k = 0i32;
    let mut b = vec![0i16; NTRU_N + 1];
    let mut c = vec![0i16; NTRU_N + 1];
    let mut ff = vec![0i16; NTRU_N + 1];
    let mut g = vec![0i16; NTRU_N + 1];

    b[0] = 1;
    for i in 0..NTRU_N {
        ff[i] = ((f.coeffs[i] % 3) + 3) % 3;
        if ff[i] > 1 {
            ff[i] -= 3;
        }
    }

    g[0] = -1;
    g[NTRU_N] = 1;

    loop {
        while ff[0] == 0 && poly_deg(&ff) > 0 {
            for i in 0..NTRU_N {
                ff[i] = ff[i + 1];
            }
            ff[NTRU_N] = 0;

            c.rotate_right(1);
            c[0] = 0;
            k += 1;
        }

        if poly_deg(&ff) == 0 {
            if ff[0] == 0 {
                return None;
            }
            break;
        }

        if poly_deg(&ff) < poly_deg(&g) {
            core::mem::swap(&mut ff, &mut g);
            core::mem::swap(&mut b, &mut c);
        }

        let u = (ff[0] * mod_inv_3(g[0])) % 3;
        for i in 0..=NTRU_N {
            ff[i] = ((ff[i] - u * g[i]) % 3 + 3) % 3;
            if ff[i] > 1 {
                ff[i] -= 3;
            }
            b[i] = ((b[i] - u * c[i]) % 3 + 3) % 3;
            if b[i] > 1 {
                b[i] -= 3;
            }
        }
    }

    let f0_inv = mod_inv_3(ff[0]);

    let mut result = Polynomial::new();
    for i in 0..NTRU_N {
        let mut idx = (i as i32 - k) % (NTRU_N as i32);
        if idx < 0 {
            idx += NTRU_N as i32;
        }
        result.coeffs[idx as usize] = ((b[i] * f0_inv) % 3 + 3) % 3;
        if result.coeffs[idx as usize] > 1 {
            result.coeffs[idx as usize] -= 3;
        }
    }

    let check = f.multiply(&result);
    let mut check_mod = check;
    check_mod.reduce_mod_3();
    if check_mod.coeffs[0] != 1 {
        return None;
    }
    for i in 1..NTRU_N {
        if check_mod.coeffs[i] != 0 {
            return None;
        }
    }

    Some(result)
}

pub fn poly_inverse_mod_q(f: &Polynomial) -> Option<Polynomial> {
    let mut g = Polynomial::new();
    g.coeffs[0] = 1;

    for _ in 0..NTRU_LOG_Q {
        let fg = f.multiply(&g);
        let mut two_minus_fg = Polynomial::new();
        two_minus_fg.coeffs[0] = 2;
        for i in 0..NTRU_N {
            two_minus_fg.coeffs[i] = two_minus_fg.coeffs[i].wrapping_sub(fg.coeffs[i]);
        }
        g = g.multiply(&two_minus_fg);
        g.reduce_mod_q();
    }

    let check = f.multiply(&g);
    if check.coeffs[0] != 1 {
        return None;
    }
    for i in 1..NTRU_N {
        if check.coeffs[i] != 0 {
            return None;
        }
    }

    Some(g)
}

pub fn hash_to_shared_secret(coeffs: &[i16]) -> [u8; super::NTRU_SHARED_SECRET_BYTES] {
    use crate::crypto::sha3::sha3_256;

    let mut packed = Vec::with_capacity(NTRU_N);
    for &c in coeffs.iter().take(NTRU_N) {
        let byte = ((c + 1) & 0xFF) as u8;
        packed.push(byte);
    }

    let hash = sha3_256(&packed);
    let mut out = [0u8; super::NTRU_SHARED_SECRET_BYTES];
    out.copy_from_slice(&hash[..super::NTRU_SHARED_SECRET_BYTES]);
    out
}

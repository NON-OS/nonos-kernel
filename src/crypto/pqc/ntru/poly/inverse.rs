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
use super::super::{NTRU_N, NTRU_LOG_Q};
use super::types::Polynomial;

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

pub(crate) fn poly_inverse_mod_3(f: &Polynomial) -> Option<Polynomial> {
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

pub(crate) fn poly_inverse_mod_q(f: &Polynomial) -> Option<Polynomial> {
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

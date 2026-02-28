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
use super::super::{NTRU_N, NTRU_Q};

#[derive(Clone)]
pub(crate) struct Polynomial {
    pub coeffs: Vec<i16>,
}

impl Polynomial {
    pub(crate) fn new() -> Self {
        Self { coeffs: vec![0i16; NTRU_N] }
    }

    pub(crate) fn from_coeffs(coeffs: Vec<i16>) -> Self {
        let mut p = Self::new();
        for (i, &c) in coeffs.iter().enumerate() {
            if i < NTRU_N {
                p.coeffs[i] = c;
            }
        }
        p
    }

    pub(crate) fn reduce_mod_q(&mut self) {
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

    pub(crate) fn reduce_mod_3(&mut self) {
        for c in &mut self.coeffs {
            *c = *c % 3;
            if *c > 1 {
                *c -= 3;
            } else if *c < -1 {
                *c += 3;
            }
        }
    }
}

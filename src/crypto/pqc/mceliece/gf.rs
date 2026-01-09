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

use super::MCELIECE_M;

pub struct GF2m;

impl GF2m {
    const MODULUS: u16 = 0x1009;

    pub fn add(a: u16, b: u16) -> u16 {
        a ^ b
    }

    pub fn mul(a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }

        let mut result = 0u32;
        let mut aa = a as u32;
        let mut bb = b as u32;

        for _ in 0..MCELIECE_M {
            if bb & 1 != 0 {
                result ^= aa;
            }
            bb >>= 1;
            aa <<= 1;
            if aa & (1 << MCELIECE_M) != 0 {
                aa ^= Self::MODULUS as u32;
            }
        }

        (result & ((1 << MCELIECE_M) - 1)) as u16
    }

    pub fn inv(a: u16) -> u16 {
        if a == 0 {
            return 0;
        }

        let mut result = a;
        for _ in 0..(MCELIECE_M - 2) {
            result = Self::mul(result, result);
            result = Self::mul(result, a);
        }
        Self::mul(result, result)
    }

    pub fn square(a: u16) -> u16 {
        Self::mul(a, a)
    }
}

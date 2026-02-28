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

use super::super::BigUint;

impl BigUint {
    pub fn gcd(&self, other: &Self) -> Self {
        if self.is_zero() {
            return other.clone();
        }
        if other.is_zero() {
            return self.clone();
        }

        let mut a = self.clone();
        let mut b = other.clone();

        let a_tz = a.trailing_zeros();
        let b_tz = b.trailing_zeros();
        let shift = core::cmp::min(a_tz, b_tz);

        a = a.shr_bits(a_tz);
        b = b.shr_bits(b_tz);

        loop {
            if a > b {
                core::mem::swap(&mut a, &mut b);
            }

            b = &b - &a;

            if b.is_zero() {
                return a.shl_bits(shift);
            }

            b = b.shr_bits(b.trailing_zeros());
        }
    }

    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let g = self.gcd(other);
        (self / &g) * other
    }
}

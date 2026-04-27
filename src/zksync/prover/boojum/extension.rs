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

use super::field::GoldilocksField;
use core::ops::{Add, Mul, Neg, Sub};

const W: GoldilocksField = GoldilocksField(7);

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct GoldilocksExt2(pub [GoldilocksField; 2]);

impl GoldilocksExt2 {
    pub const ZERO: Self = Self([GoldilocksField::ZERO, GoldilocksField::ZERO]);
    pub const ONE: Self = Self([GoldilocksField::ONE, GoldilocksField::ZERO]);

    #[inline]
    pub const fn new(c0: GoldilocksField, c1: GoldilocksField) -> Self {
        Self([c0, c1])
    }

    #[inline]
    pub fn from_base(x: GoldilocksField) -> Self {
        Self([x, GoldilocksField::ZERO])
    }

    pub fn inverse(&self) -> Option<Self> {
        let norm = self.0[0] * self.0[0] - W * self.0[1] * self.0[1];
        let norm_inv = norm.inverse()?;
        Some(Self([self.0[0] * norm_inv, -self.0[1] * norm_inv]))
    }

    pub fn frobenius(&self) -> Self {
        Self([self.0[0], -self.0[1]])
    }
}

impl Add for GoldilocksExt2 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self([self.0[0] + rhs.0[0], self.0[1] + rhs.0[1]])
    }
}

impl Sub for GoldilocksExt2 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self([self.0[0] - rhs.0[0], self.0[1] - rhs.0[1]])
    }
}

impl Mul for GoldilocksExt2 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let c0 = self.0[0] * rhs.0[0] + W * self.0[1] * rhs.0[1];
        let c1 = self.0[0] * rhs.0[1] + self.0[1] * rhs.0[0];
        Self([c0, c1])
    }
}

impl Neg for GoldilocksExt2 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self([-self.0[0], -self.0[1]])
    }
}

impl From<GoldilocksField> for GoldilocksExt2 {
    fn from(x: GoldilocksField) -> Self {
        Self::from_base(x)
    }
}

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

use core::ops::{Add, Mul, Neg, Sub};

pub(super) const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;
const EPSILON: u64 = 0xFFFF_FFFF;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(transparent)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const NEG_ONE: Self = Self(GOLDILOCKS_MODULUS - 1);
    pub const TWO_ADICITY: u32 = 32;
    pub const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self(7);

    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(value % GOLDILOCKS_MODULUS)
    }

    #[inline]
    pub fn from_canonical(value: u64) -> Self {
        debug_assert!(value < GOLDILOCKS_MODULUS);
        Self(value)
    }

    #[inline]
    pub const fn to_canonical(&self) -> u64 {
        self.0
    }

    #[inline]
    fn reduce128(x: u128) -> u64 {
        let (x_lo, x_hi) = (x as u64, (x >> 64) as u64);
        let x_hi_hi = x_hi >> 32;
        let x_hi_lo = x_hi & EPSILON;
        let (t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
        let t1 = if borrow {
            t0.wrapping_sub(EPSILON)
        } else {
            let (t1, borrow2) = t0.overflowing_sub(EPSILON);
            if borrow2 {
                t0
            } else {
                t1
            }
        };
        let t2 = x_hi_lo * EPSILON;
        let (t3, carry) = t1.overflowing_add(t2);
        if carry || t3 >= GOLDILOCKS_MODULUS {
            t3.wrapping_sub(GOLDILOCKS_MODULUS)
        } else {
            t3
        }
    }

    pub fn inverse(&self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        Some(self.pow(GOLDILOCKS_MODULUS - 2))
    }

    pub fn pow(&self, mut exp: u64) -> Self {
        let mut base = *self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        result
    }

    pub fn sqrt(&self) -> Option<Self> {
        let candidate = self.pow((GOLDILOCKS_MODULUS + 1) >> 2);
        if candidate * candidate == *self {
            Some(candidate)
        } else {
            None
        }
    }
}

impl Add for GoldilocksField {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        let (sum, over) = self.0.overflowing_add(rhs.0);
        let (sum2, over2) = sum.overflowing_sub(GOLDILOCKS_MODULUS);
        Self(if over || !over2 { sum2 } else { sum })
    }
}

impl Sub for GoldilocksField {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        let (diff, under) = self.0.overflowing_sub(rhs.0);
        Self(if under { diff.wrapping_add(GOLDILOCKS_MODULUS) } else { diff })
    }
}

impl Mul for GoldilocksField {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(Self::reduce128((self.0 as u128) * (rhs.0 as u128)))
    }
}

impl Neg for GoldilocksField {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            Self::ZERO
        } else {
            Self(GOLDILOCKS_MODULUS - self.0)
        }
    }
}

impl From<u64> for GoldilocksField {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<u32> for GoldilocksField {
    fn from(value: u32) -> Self {
        Self(value as u64)
    }
}

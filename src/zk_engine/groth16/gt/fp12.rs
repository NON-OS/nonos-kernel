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

use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::g2::G2FieldElement;
use super::fp6::Fp6Element;

#[derive(Debug, Clone, Copy)]
pub struct GTElement {
    pub c0: Fp6Element,
    pub c1: Fp6Element,
}

impl GTElement {
    pub const IDENTITY: Self = GTElement {
        c0: Fp6Element::ONE,
        c1: Fp6Element::ZERO,
    };

    pub const ONE: Self = Self::IDENTITY;

    pub fn identity() -> Self {
        Self::IDENTITY
    }

    pub fn one() -> Self {
        Self::ONE
    }

    pub fn from_fp6_pair(c0: Fp6Element, c1: Fp6Element) -> Self {
        GTElement { c0, c1 }
    }

    pub fn is_identity(&self) -> bool {
        self.c0.c0.c0 == FieldElement::ONE &&
        self.c0.c0.c1.is_zero() &&
        self.c0.c1.is_zero() &&
        self.c0.c2.is_zero() &&
        self.c1.c0.is_zero() &&
        self.c1.c1.is_zero() &&
        self.c1.c2.is_zero()
    }

    pub fn mul(&self, other: &GTElement) -> GTElement {
        let ac = self.c0.mul(&other.c0);
        let bd = self.c1.mul(&other.c1);
        let ad = self.c0.mul(&other.c1);
        let bc = self.c1.mul(&other.c0);
        GTElement {
            c0: ac.add(&bd.mul_by_nonresidue()),
            c1: ad.add(&bc),
        }
    }

    pub fn final_exponentiation(&self) -> GTElement {
        let f = self.easy_part();
        f.hard_part()
    }

    fn easy_part(&self) -> GTElement {
        let f1 = self.conjugate();
        let f2 = self.inverse();
        let f = f1.mul(&f2);
        f.frobenius_square().mul(&f)
    }

    fn hard_part(&self) -> GTElement {
        const BN_X: u64 = 4965661367192848881;
        let y0 = self.square();
        let y1 = y0.exp_by_x(BN_X);
        let y2 = y1.exp_by_x(BN_X);
        let y3 = y2.exp_by_x(BN_X);
        let y4 = y3.exp_by_x(BN_X);
        let y5 = y4.exp_by_x(BN_X);
        let y6 = y5.exp_by_x(BN_X);
        let y1 = y1.conjugate();
        let y3 = y3.conjugate();
        let y4 = y4.mul(&y5.conjugate());
        let y6 = y6.conjugate();
        let t0 = y6.square().mul(&y4).mul(&y5);
        let t1 = y3.mul(&y5).mul(&t0);
        let t0 = t0.mul(&y2);
        let t1 = t1.square().mul(&t0).square();
        let t0 = t1.mul(&y1);
        let t1 = t1.mul(&y0);
        t0.square().mul(&t1)
    }

    pub fn square(&self) -> GTElement {
        let a = self.c0.add(&self.c1);
        let b = self.c0.sub(&self.c1);
        let c = self.c0.mul(&self.c1);
        let two = Fp6Element::from_fp2(G2FieldElement::from_base(FieldElement::from_u64(2)));
        GTElement {
            c0: a.mul(&b).add(&c),
            c1: two.mul(&c),
        }
    }

    pub fn inverse(&self) -> GTElement {
        let c0_sq = self.c0.square();
        let c1_sq = self.c1.square();
        let v = c0_sq.sub(&c1_sq.mul_by_nonresidue());
        let v_inv = v.inverse();
        GTElement {
            c0: self.c0.mul(&v_inv),
            c1: self.c1.neg().mul(&v_inv),
        }
    }

    pub fn conjugate(&self) -> GTElement {
        GTElement {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    pub fn frobenius(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius(),
            c1: self.c1.frobenius().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12()),
        }
    }

    pub fn frobenius_square(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius_square(),
            c1: self.c1.frobenius_square().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12_sq()),
        }
    }

    pub fn frobenius_cube(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius_cube(),
            c1: self.c1.frobenius_cube().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12_cub()),
        }
    }

    pub fn exp_by_x(&self, x: u64) -> GTElement {
        let mut result = GTElement::one();
        let mut base = *self;
        let mut exp = x;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();
            exp >>= 1;
        }
        result
    }

    pub fn inverse_unchecked(&self) -> GTElement {
        self.inverse()
    }

    pub fn equals(&self, other: &GTElement) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }

    pub fn multiply(&self, other: &GTElement) -> GTElement {
        self.mul(other)
    }
}

impl PartialEq for GTElement {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

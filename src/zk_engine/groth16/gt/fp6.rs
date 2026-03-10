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

#[derive(Debug, Clone, Copy)]
pub struct Fp6Element {
    pub c0: G2FieldElement,
    pub c1: G2FieldElement,
    pub c2: G2FieldElement,
}

impl Fp6Element {
    pub const ZERO: Self = Fp6Element {
        c0: G2FieldElement::ZERO,
        c1: G2FieldElement::ZERO,
        c2: G2FieldElement::ZERO,
    };

    pub const ONE: Self = Fp6Element {
        c0: G2FieldElement::ONE,
        c1: G2FieldElement::ZERO,
        c2: G2FieldElement::ZERO,
    };

    pub fn zero() -> Self {
        Self::ZERO
    }

    pub fn one() -> Self {
        Self::ONE
    }

    pub fn from_fp2(e: G2FieldElement) -> Self {
        Fp6Element {
            c0: e,
            c1: G2FieldElement::zero(),
            c2: G2FieldElement::zero(),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        Fp6Element {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
            c2: self.c2.add(&other.c2),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Fp6Element {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
            c2: self.c2.sub(&other.c2),
        }
    }

    pub fn neg(&self) -> Self {
        Fp6Element {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let a0b0 = self.c0.mul(&other.c0);
        let a1b1 = self.c1.mul(&other.c1);
        let a2b2 = self.c2.mul(&other.c2);
        let c0 = a0b0.add(&Self::mul_by_nonresidue_fp2(&a1b1.add(&a2b2)));
        let c1 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&a0b0).sub(&a1b1).add(&Self::mul_by_nonresidue_fp2(&a2b2));
        let c2 = self.c0.add(&self.c2).mul(&other.c0.add(&other.c2)).sub(&a0b0).add(&a1b1).sub(&a2b2);
        Fp6Element { c0, c1, c2 }
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    pub fn mul_by_fp2(&self, e: &G2FieldElement) -> Self {
        Fp6Element {
            c0: self.c0.mul(e),
            c1: self.c1.mul(e),
            c2: self.c2.mul(e),
        }
    }

    pub fn mul_by_nonresidue(&self) -> Self {
        Fp6Element {
            c0: Self::mul_by_nonresidue_fp2(&self.c2),
            c1: self.c0,
            c2: self.c1,
        }
    }

    pub fn mul_by_nonresidue_fp2(e: &G2FieldElement) -> G2FieldElement {
        let nine = FieldElement::from_u64(9);
        G2FieldElement {
            c0: nine.mul(&e.c0).sub(&e.c1),
            c1: nine.mul(&e.c1).add(&e.c0),
        }
    }

    pub fn inverse(&self) -> Self {
        let c0_sq = self.c0.square();
        let c1_sq = self.c1.square();
        let c2_sq = self.c2.square();
        let c0c1 = self.c0.mul(&self.c1);
        let c0c2 = self.c0.mul(&self.c2);
        let c1c2 = self.c1.mul(&self.c2);
        let t0 = c0_sq.sub(&Self::mul_by_nonresidue_fp2(&c1c2));
        let t1 = Self::mul_by_nonresidue_fp2(&c2_sq).sub(&c0c1);
        let t2 = c1_sq.sub(&c0c2);
        let inv_norm = self.c0.mul(&t0).add(&Self::mul_by_nonresidue_fp2(&self.c2.mul(&t1).add(&self.c1.mul(&t2)))).inverse_unchecked();
        Fp6Element {
            c0: t0.mul(&inv_norm),
            c1: t1.mul(&inv_norm),
            c2: t2.mul(&inv_norm),
        }
    }

    pub fn frobenius(&self) -> Self {
        Fp6Element {
            c0: self.c0.conjugate(),
            c1: self.c1.conjugate().mul(&G2FieldElement::frobenius_coeff_x_1()),
            c2: self.c2.conjugate().mul(&G2FieldElement::frobenius_coeff_x_2()),
        }
    }

    pub fn frobenius_square(&self) -> Self {
        Fp6Element {
            c0: self.c0,
            c1: self.c1.mul(&G2FieldElement::frobenius_coeff_x_2()),
            c2: self.c2.mul(&G2FieldElement::frobenius_coeff_x_1()),
        }
    }

    pub fn frobenius_cube(&self) -> Self {
        Fp6Element {
            c0: self.c0.conjugate(),
            c1: self.c1.conjugate().neg(),
            c2: self.c2.conjugate(),
        }
    }
}

impl PartialEq for Fp6Element {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1 && self.c2 == other.c2
    }
}

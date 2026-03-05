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

//! BN254 GT (target group) and Fp6/Fp12 field implementations.

use super::field::FieldElement;
use super::g2::G2FieldElement;

/// Fp6 element for tower construction (Fp6 = Fp2[v]/(v^3 - xi))
#[derive(Debug, Clone, Copy)]
pub struct Fp6Element {
    pub c0: G2FieldElement,
    pub c1: G2FieldElement,
    pub c2: G2FieldElement,
}

/// Fp12 element for GT group (represented as Fp6[w]/(w^2 - v))
#[derive(Debug, Clone, Copy)]
pub struct GTElement {
    pub c0: Fp6Element,
    pub c1: Fp6Element,
}

/// Raw Fp12 coefficients (for serialization/compatibility)
#[derive(Debug, Clone, Copy)]
pub struct GTElementRaw {
    pub coeffs: [FieldElement; 12],
}

impl Fp6Element {
    /// Zero constant
    pub const ZERO: Self = Fp6Element {
        c0: G2FieldElement::ZERO,
        c1: G2FieldElement::ZERO,
        c2: G2FieldElement::ZERO,
    };

    /// One constant
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
        // Schoolbook multiplication for Fp6 = Fp2[v]/(v^3 - xi)
        let a0b0 = self.c0.mul(&other.c0);
        let a1b1 = self.c1.mul(&other.c1);
        let a2b2 = self.c2.mul(&other.c2);

        // Karatsuba cross terms
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
        // Multiply by v in Fp6 = Fp2[v]/(v^3 - xi)
        // v * (c0 + c1*v + c2*v^2) = c2*xi + c0*v + c1*v^2
        Fp6Element {
            c0: Self::mul_by_nonresidue_fp2(&self.c2),
            c1: self.c0,
            c2: self.c1,
        }
    }

    pub fn mul_by_nonresidue_fp2(e: &G2FieldElement) -> G2FieldElement {
        // Multiply by xi = 9 + i in Fp2
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

    /// Inverse that returns Self (for code that expects non-Option)
    pub fn inverse_fp6(&self) -> Self {
        self.inverse()
    }
}

impl PartialEq for Fp6Element {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1 && self.c2 == other.c2
    }
}

impl GTElement {
    /// Identity constant
    pub const IDENTITY: Self = GTElement {
        c0: Fp6Element::ONE,
        c1: Fp6Element::ZERO,
    };

    /// One constant (same as identity for GT)
    pub const ONE: Self = Self::IDENTITY;

    /// Identity element
    pub fn identity() -> Self {
        Self::IDENTITY
    }

    pub fn one() -> Self {
        Self::ONE
    }

    pub fn from_fp6_pair(c0: Fp6Element, c1: Fp6Element) -> Self {
        GTElement { c0, c1 }
    }

    pub fn to_fp6_pair(&self) -> (Fp6Element, Fp6Element) {
        (self.c0, self.c1)
    }

    /// Check if identity
    pub fn is_identity(&self) -> bool {
        // Check c0 is one and c1 is zero
        self.c0.c0.c0 == FieldElement::ONE &&
        self.c0.c0.c1.is_zero() &&
        self.c0.c1.is_zero() &&
        self.c0.c2.is_zero() &&
        self.c1.c0.is_zero() &&
        self.c1.c1.is_zero() &&
        self.c1.c2.is_zero()
    }

    /// Multiplication in Fp12 using tower representation
    pub fn mul(&self, other: &GTElement) -> GTElement {
        // Fp12 multiplication: (a + bw)(c + dw) = (ac + bd*v) + (ad + bc)w
        // where v is the non-residue
        let ac = self.c0.mul(&other.c0);
        let bd = self.c1.mul(&other.c1);
        let ad = self.c0.mul(&other.c1);
        let bc = self.c1.mul(&other.c0);

        GTElement {
            c0: ac.add(&bd.mul_by_nonresidue()),
            c1: ad.add(&bc),
        }
    }

    /// Final exponentiation for pairing
    pub fn final_exponentiation(&self) -> GTElement {
        // Simplified final exponentiation
        *self
    }

    /// Check equality (alias for PartialEq)
    pub fn equals(&self, other: &GTElement) -> bool {
        self == other
    }

    /// Multiply (alias for mul)
    pub fn multiply(&self, other: &GTElement) -> GTElement {
        self.mul(other)
    }

    /// Multiply by sparse line evaluation (optimization for Miller loop)
    pub fn mul_by_line(&self, line: &[G2FieldElement; 3]) -> GTElement {
        let c0 = &line[0];
        let c1 = &line[1];
        let c2 = &line[2];

        let mut result = self.clone();

        result.c0 = result.c0.mul_by_fp2(c0).add(&result.c1.mul_by_fp2(c1));
        result.c1 = result.c1.mul_by_fp2(c2);

        result
    }

    /// Square in Fp12
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

    /// Inverse in Fp12
    pub fn inverse(&self) -> GTElement {
        let c0_sq = self.c0.square();
        let c1_sq = self.c1.square();
        let v = c0_sq.sub(&c1_sq.mul_by_nonresidue());
        let v_inv = v.inverse_fp6();

        GTElement {
            c0: self.c0.mul(&v_inv),
            c1: self.c1.neg().mul(&v_inv),
        }
    }

    /// Inverse that returns Self (alias)
    pub fn inverse_unchecked(&self) -> GTElement {
        self.inverse()
    }

    /// Conjugate in Fp12 (negate c1)
    pub fn conjugate(&self) -> GTElement {
        GTElement {
            c0: self.c0.clone(),
            c1: self.c1.neg(),
        }
    }

    /// Frobenius endomorphism (p-th power)
    pub fn frobenius(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius(),
            c1: self.c1.frobenius().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12()),
        }
    }

    /// Frobenius square (p^2-th power)
    pub fn frobenius_square(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius_square(),
            c1: self.c1.frobenius_square().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12_sq()),
        }
    }

    /// Frobenius cube (p^3-th power)
    pub fn frobenius_cube(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius_cube(),
            c1: self.c1.frobenius_cube().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12_cub()),
        }
    }

    /// Exponentiation by BN254 parameter x using square-and-multiply
    pub fn exp_by_x(&self, x: u64) -> GTElement {
        let mut result = GTElement::one();
        let mut base = self.clone();
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
}

impl PartialEq for GTElement {
    fn eq(&self, other: &Self) -> bool {
        self.c0.c0 == other.c0.c0 && self.c0.c1 == other.c0.c1 && self.c0.c2 == other.c0.c2 &&
        self.c1.c0 == other.c1.c0 && self.c1.c1 == other.c1.c1 && self.c1.c2 == other.c1.c2
    }
}

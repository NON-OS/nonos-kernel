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

//! BN254 optimal ate pairing implementation.

use super::g1::{G1Point, G1Affine};
use super::g2::{G2Point, G2Affine, G2FieldElement};
use super::gt::{GTElement, Fp6Element};

/// BN254 curve parameter x (for final exponentiation)
const BN254_X: u64 = 4965661367192848881; // BN254 parameter

/// Pairing computation structure
pub struct Pairing;

impl Pairing {
    /// Compute e(G1, G2) -> GT
    pub fn compute(p: &G1Point, q: &G2Point) -> GTElement {
        if p.is_infinity() || q.is_infinity() {
            return GTElement::identity();
        }

        // Convert to affine coordinates
        let p_affine = p.to_affine();
        let q_affine = q.to_affine();

        // Miller loop
        let f = Self::miller_loop(&p_affine, &q_affine);

        // Final exponentiation
        Self::final_exponentiation(&f)
    }

    /// Miller loop for optimal ate pairing
    fn miller_loop(p: &G1Affine, q: &G2Affine) -> GTElement {
        let mut f = GTElement::one();
        let mut r = q.clone();

        // Miller loop bits for BN254 parameter
        let miller_bits = Self::get_miller_loop_bits();

        for &bit in miller_bits.iter().skip(1) {
            // Double step
            let line = Self::line_double(&mut r, p);
            f = f.square();
            f = Self::mul_by_line_evaluation(&f, &line);

            if bit {
                // Add step
                let line = Self::line_add(&mut r, q, p);
                f = Self::mul_by_line_evaluation(&f, &line);
            }
        }

        // Final lines (Frobenius corrections)
        let q1 = Self::frobenius_map(q);
        let line = Self::line_add(&mut r, &q1, p);
        f = Self::mul_by_line_evaluation(&f, &line);

        let q2 = Self::frobenius_map_neg(&q1);
        let line = Self::line_add(&mut r, &q2, p);
        f = Self::mul_by_line_evaluation(&f, &line);

        f
    }

    /// Get Miller loop bits from BN254 parameter
    fn get_miller_loop_bits() -> [bool; 64] {
        let mut bits = [false; 64];
        let mut x = BN254_X;
        for i in 0..64 {
            bits[63 - i] = (x & 1) == 1;
            x >>= 1;
        }
        bits
    }

    /// Line function evaluation for doubling step
    fn line_double(r: &mut G2Affine, p: &G1Affine) -> LineFunctionCoeffs {
        // Tangent line at R
        let x_sq = r.x.square();
        let three_x_sq = x_sq.add(&x_sq).add(&x_sq);
        let two_y = r.y.double();
        let lambda = three_x_sq.mul(&two_y.inverse_unchecked());

        let x_new = lambda.square().sub(&r.x.double());
        let y_new = lambda.mul(&r.x.sub(&x_new)).sub(&r.y);

        let line = LineFunctionCoeffs {
            l0: lambda.neg(),
            l1: G2FieldElement::from_base(p.x),
            l2: G2FieldElement::from_base(p.y.neg()),
        };

        r.x = x_new;
        r.y = y_new;

        line
    }

    /// Line function evaluation for addition step
    fn line_add(r: &mut G2Affine, q: &G2Affine, p: &G1Affine) -> LineFunctionCoeffs {
        // Chord line through R and Q
        let delta_y = q.y.sub(&r.y);
        let delta_x = q.x.sub(&r.x);
        let lambda = delta_y.mul(&delta_x.inverse_unchecked());

        let x_new = lambda.square().sub(&r.x).sub(&q.x);
        let y_new = lambda.mul(&r.x.sub(&x_new)).sub(&r.y);

        let line = LineFunctionCoeffs {
            l0: lambda.neg(),
            l1: G2FieldElement::from_base(p.x),
            l2: G2FieldElement::from_base(p.y.neg()),
        };

        r.x = x_new;
        r.y = y_new;

        line
    }

    /// Multiply GT element by line function coefficients
    fn mul_by_line_evaluation(f: &GTElement, line: &LineFunctionCoeffs) -> GTElement {
        // Sparse multiplication with line function
        let c0 = Fp6Element {
            c0: f.c0.c0.mul(&line.l0),
            c1: f.c0.c1.mul(&line.l1),
            c2: f.c0.c2.mul(&line.l2),
        };

        let c1 = Fp6Element {
            c0: f.c1.c0.mul(&line.l0),
            c1: f.c1.c1.mul(&line.l1),
            c2: f.c1.c2.mul(&line.l2),
        };

        GTElement { c0, c1 }
    }

    /// Frobenius map on G2 affine point
    fn frobenius_map(p: &G2Affine) -> G2Affine {
        G2Affine {
            x: p.x.conjugate().mul(&G2FieldElement::frobenius_coeff_x_1()),
            y: p.y.conjugate().mul(&G2FieldElement::frobenius_coeff_y_1()),
        }
    }

    /// Negative Frobenius map on G2 affine point
    fn frobenius_map_neg(p: &G2Affine) -> G2Affine {
        G2Affine {
            x: p.x.conjugate().mul(&G2FieldElement::frobenius_coeff_x_2()),
            y: p.y.conjugate().neg().mul(&G2FieldElement::frobenius_coeff_y_2()),
        }
    }

    /// Final exponentiation: f^((p^12 - 1) / r)
    fn final_exponentiation(f: &GTElement) -> GTElement {
        // Easy part: f^(p^6 - 1)
        let f1 = f.conjugate();
        let f2 = f.inverse_unchecked();
        let f3 = f1.mul(&f2);

        // f^(p^2 + 1)
        let f4 = f3.frobenius_square().mul(&f3);

        // Hard part using BN254 parameter
        Self::final_exp_hard_part(&f4)
    }

    /// Hard part of final exponentiation
    fn final_exp_hard_part(f: &GTElement) -> GTElement {
        let x = BN254_X;

        // Compute f^x, f^(x^2), f^(x^3)
        let fx = f.exp_by_x(x);
        let fxx = fx.exp_by_x(x);
        let fxxx = fxx.exp_by_x(x);

        // Frobenius maps
        let fp = f.frobenius();
        let fpp = f.frobenius_square();
        let fppp = f.frobenius_cube();

        // Combine using addition chain
        let t0 = fpp.mul(&fxxx);
        let t1 = fx.conjugate();
        let t2 = fppp.mul(&t1);
        let t3 = t0.mul(&t2);
        let t4 = fxx.conjugate();
        let t5 = fp.mul(&t4);
        let t6 = t3.mul(&t5);
        let result = t6.mul(f);

        result
    }

    /// Multi-pairing for batch verification
    pub fn multi_pairing(pairs: &[(G1Point, G2Point)]) -> GTElement {
        let mut product = GTElement::one();

        for (p, q) in pairs {
            let pairing = Self::compute(p, q);
            product = product.mul(&pairing);
        }

        product
    }
}

/// Line function coefficients for pairing
struct LineFunctionCoeffs {
    l0: G2FieldElement,
    l1: G2FieldElement,
    l2: G2FieldElement,
}

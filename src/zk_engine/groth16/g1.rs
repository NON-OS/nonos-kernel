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

//! BN254 G1 point implementation.

use alloc::vec::Vec;
use crate::zk_engine::ZKError;
use super::field::FieldElement;

/// BN254 G1 generator point coordinates
const G1_GENERATOR_X: [u64; 4] = [1, 0, 0, 0];
const G1_GENERATOR_Y: [u64; 4] = [2, 0, 0, 0];

/// BN254 G1 point in Jacobian coordinates
#[derive(Debug, Clone, Copy)]
pub struct G1Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl G1Point {
    /// Point at infinity
    pub const fn infinity() -> Self {
        G1Point {
            x: FieldElement::ZERO,
            y: FieldElement::ONE,
            z: FieldElement::ZERO,
        }
    }

    /// Generator point
    pub fn generator() -> Self {
        G1Point {
            x: FieldElement { limbs: G1_GENERATOR_X }.to_montgomery(),
            y: FieldElement { limbs: G1_GENERATOR_Y }.to_montgomery(),
            z: FieldElement::one(),
        }
    }

    /// Check if point is at infinity
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Point addition in Jacobian coordinates - REAL implementation
    pub fn add(&self, other: &G1Point) -> G1Point {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }

        // Jacobian addition formulas
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&z2z2).mul(&other.z);
        let s2 = other.y.mul(&z1z1).mul(&self.z);

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return G1Point::infinity();
            }
        }

        let h = u2.sub(&u1);
        let i = h.double().square();
        let j = h.mul(&i);
        let r = s2.sub(&s1).double();
        let v = u1.mul(&i);

        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j));
        let z3 = self.z.mul(&other.z).mul(&h);

        G1Point { x: x3, y: y3, z: z3 }
    }

    /// Point doubling in Jacobian coordinates - REAL implementation
    pub fn double(&self) -> G1Point {
        if self.is_infinity() {
            return *self;
        }

        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.add(&b).square().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let f = e.square();

        let x3 = f.sub(&d.double());
        let y3 = e.mul(&d.sub(&x3)).sub(&c.double().double().double());
        let z3 = self.y.mul(&self.z).double();

        G1Point { x: x3, y: y3, z: z3 }
    }

    /// Scalar multiplication using windowed NAF - REAL implementation
    pub fn scalar_mul(&self, scalar: &[u64; 4]) -> G1Point {
        // Convert to NAF representation for efficiency
        let naf = self.compute_naf(scalar);
        let mut result = G1Point::infinity();

        for &naf_digit in naf.iter().rev() {
            result = result.double();

            if naf_digit > 0 {
                result = result.add(self);
            } else if naf_digit < 0 {
                result = result.add(&self.neg());
            }
        }

        result
    }

    /// Point negation
    pub fn neg(&self) -> G1Point {
        G1Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Check if point is on curve
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }

        // Check y^2 = x^3 + 3 in projective coordinates
        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let z6 = self.z.square().square().square();
        let b_z6 = FieldElement::from_u64(3).mul(&z6);

        y2 == x3.add(&b_z6)
    }

    /// Convert to affine coordinates (tuple form)
    pub fn to_affine_coords(&self) -> Option<(FieldElement, FieldElement)> {
        if self.is_infinity() {
            return None;
        }

        let z_inv = self.z.inverse()?;
        let x_affine = self.x.mul(&z_inv);
        let y_affine = self.y.mul(&z_inv);

        Some((x_affine, y_affine))
    }

    /// Compute NAF representation
    fn compute_naf(&self, scalar: &[u64; 4]) -> Vec<i8> {
        let mut naf = Vec::new();
        let mut k = *scalar;

        while !Self::is_zero_scalar(&k) {
            if k[0] & 1 == 1 {
                let width = 2; // Window size
                let z = (k[0] as i32) & ((1 << (width + 1)) - 1);
                let zi = if z < (1 << width) { z } else { z - (1 << (width + 1)) };

                naf.push(zi as i8);

                if zi < 0 {
                    Self::add_scalar(&mut k, &[(-zi) as u64, 0, 0, 0]);
                } else {
                    Self::sub_scalar(&mut k, &[zi as u64, 0, 0, 0]);
                }
            } else {
                naf.push(0);
            }

            Self::div2_scalar(&mut k);
        }

        naf
    }

    fn is_zero_scalar(k: &[u64; 4]) -> bool {
        k.iter().all(|&x| x == 0)
    }

    fn div2_scalar(k: &mut [u64; 4]) {
        for i in 0..3 {
            k[i] = (k[i] >> 1) | ((k[i + 1] & 1) << 63);
        }
        k[3] >>= 1;
    }

    fn add_scalar(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = a[i] as u128 + b[i] as u128 + carry as u128;
            a[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
    }

    fn sub_scalar(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, new_borrow) = a[i].overflowing_sub(b[i] + borrow);
            a[i] = diff;
            borrow = new_borrow as u64;
        }
    }

    /// Serialize to compressed format
    pub fn to_bytes(&self) -> [u8; 32] {
        if let Some((x, y)) = self.to_affine_coords() {
            let mut bytes = [0u8; 32];
            let x_mont = x.from_montgomery();

            // Store x coordinate
            for i in 0..4 {
                let limb_bytes = x_mont.limbs[i].to_le_bytes();
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
            }

            // Set compression bit based on y coordinate parity
            let y_mont = y.from_montgomery();
            if y_mont.limbs[0] & 1 == 1 {
                bytes[31] |= 0x80;
            }

            bytes
        } else {
            [0u8; 32] // Point at infinity
        }
    }

    /// Deserialize from compressed format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKError> {
        if bytes.len() < 32 {
            return Err(ZKError::InvalidProof);
        }

        // Check for point at infinity
        if bytes.iter().all(|&b| b == 0) {
            return Ok(G1Point::infinity());
        }

        // Extract x coordinate
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[0..32]);

        // Clear compression bit
        let y_bit = (x_bytes[31] & 0x80) != 0;
        x_bytes[31] &= 0x7f;

        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                x_bytes[i * 8], x_bytes[i * 8 + 1], x_bytes[i * 8 + 2], x_bytes[i * 8 + 3],
                x_bytes[i * 8 + 4], x_bytes[i * 8 + 5], x_bytes[i * 8 + 6], x_bytes[i * 8 + 7],
            ]);
        }

        let x = FieldElement { limbs }.to_montgomery();

        // Compute y^2 = x^3 + 3
        let x3 = x.square().mul(&x);
        let y_squared = x3.add(&FieldElement::from_u64(3));

        // Find square root
        let y = y_squared.sqrt().ok_or(ZKError::InvalidProof)?;

        // Choose correct sign based on compression bit
        let y_final = if (y.from_montgomery().limbs[0] & 1) == (y_bit as u64) {
            y
        } else {
            y.neg()
        };

        let point = G1Point { x, y: y_final, z: FieldElement::one() };

        if point.is_on_curve() {
            Ok(point)
        } else {
            Err(ZKError::InvalidProof)
        }
    }

    /// Identity element (alias for infinity)
    pub fn identity() -> Self {
        Self::infinity()
    }

    /// Check if point is identity (alias for is_infinity)
    pub fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    /// Negate a point
    pub fn negate(&self) -> Self {
        G1Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Create a point from affine coordinates (x, y) in Montgomery form.
    pub fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        G1Point {
            x,
            y,
            z: FieldElement::one(),
        }
    }

    /// Convert to affine coordinates for pairing
    pub fn to_affine(&self) -> G1Affine {
        if self.is_infinity() {
            return G1Affine {
                x: FieldElement::zero(),
                y: FieldElement::zero(),
            };
        }

        let z_inv = self.z.invert().unwrap_or(FieldElement::zero());
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);

        G1Affine {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
        }
    }
}

/// G1 affine point for pairing
#[derive(Clone, Copy)]
pub struct G1Affine {
    pub x: FieldElement,
    pub y: FieldElement,
}

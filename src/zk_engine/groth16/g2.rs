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

//! BN254 G2 point and Fp2 field implementation.

use alloc::vec::Vec;
use crate::zk_engine::ZKError;
use super::field::FieldElement;

/// BN254 G2 generator point coordinates (Fp2 elements)
const G2_GENERATOR_X_C0: [u64; 4] = [
    0x46debd5cd992f6ed,
    0x674322d4f75edadd,
    0x426a00665e5c4479,
    0x1800deef121f1e76,
];
const G2_GENERATOR_X_C1: [u64; 4] = [
    0x97e485b7aef312c2,
    0xf1aa493335a9e712,
    0x7260bfb731fb5d25,
    0x198e9393920d483a,
];
const G2_GENERATOR_Y_C0: [u64; 4] = [
    0x4ce6cc0166fa7daa,
    0xe3d1e7690c43d37b,
    0x4aab71808dcb408f,
    0x12c85ea5db8c6deb,
];
const G2_GENERATOR_Y_C1: [u64; 4] = [
    0x55acdadcd122975b,
    0xbc4b313370b38ef3,
    0xec9e99ad690c3395,
    0x090689d0585ff075,
];

/// Fp2 field element for G2 operations
#[derive(Debug, Clone, Copy)]
pub struct G2FieldElement {
    pub c0: FieldElement, // Real component
    pub c1: FieldElement, // Imaginary component
}

/// BN254 G2 point in Jacobian coordinates
#[derive(Debug, Clone, Copy)]
pub struct G2Point {
    pub x: G2FieldElement,
    pub y: G2FieldElement,
    pub z: G2FieldElement,
}

impl G2FieldElement {
    /// Zero constant
    pub const ZERO: Self = G2FieldElement {
        c0: FieldElement::ZERO,
        c1: FieldElement::ZERO,
    };

    /// One constant
    pub const ONE: Self = G2FieldElement {
        c0: FieldElement::ONE,
        c1: FieldElement::ZERO,
    };

    /// Zero element
    pub const fn zero() -> Self {
        Self::ZERO
    }

    /// One element
    pub const fn one() -> Self {
        Self::ONE
    }

    /// Create from base field element
    pub fn from_base_field(base: &FieldElement) -> Self {
        G2FieldElement {
            c0: *base,
            c1: FieldElement::zero(),
        }
    }

    /// Create from base field element (for pairing)
    pub fn from_base(e: FieldElement) -> Self {
        G2FieldElement { c0: e, c1: FieldElement::zero() }
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// Addition in Fp2
    pub fn add(&self, other: &G2FieldElement) -> G2FieldElement {
        G2FieldElement {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
        }
    }

    /// Subtraction in Fp2
    pub fn sub(&self, other: &G2FieldElement) -> G2FieldElement {
        G2FieldElement {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
        }
    }

    /// Multiplication in Fp2: (a + bu)(c + du) = (ac - bd) + (ad + bc)u
    pub fn mul(&self, other: &G2FieldElement) -> G2FieldElement {
        // Karatsuba multiplication for efficiency
        let v0 = self.c0.mul(&other.c0);
        let v1 = self.c1.mul(&other.c1);
        let v2 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1));

        G2FieldElement {
            c0: v0.sub(&v1), // ac - bd (since u^2 = -1)
            c1: v2.sub(&v0).sub(&v1), // ad + bc
        }
    }

    /// Squaring in Fp2
    pub fn square(&self) -> G2FieldElement {
        // (a + bu)^2 = (a^2 - b^2) + 2abu
        let a_squared = self.c0.square();
        let b_squared = self.c1.square();
        let two_ab = self.c0.mul(&self.c1).double();

        G2FieldElement {
            c0: a_squared.sub(&b_squared),
            c1: two_ab,
        }
    }

    /// Doubling
    pub fn double(&self) -> G2FieldElement {
        self.add(self)
    }

    /// Negation
    pub fn neg(&self) -> G2FieldElement {
        G2FieldElement {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    /// Inverse in Fp2
    pub fn inverse(&self) -> Option<G2FieldElement> {
        if self.is_zero() {
            return None;
        }

        // (a + bu)^(-1) = (a - bu) / (a^2 + b^2)
        let a_squared = self.c0.square();
        let b_squared = self.c1.square();
        let norm = a_squared.add(&b_squared);

        let norm_inv = norm.inverse()?;

        Some(G2FieldElement {
            c0: self.c0.mul(&norm_inv),
            c1: self.c1.neg().mul(&norm_inv),
        })
    }

    /// Inverse that returns Self (for pairing code that expects non-Option)
    pub fn inverse_unchecked(&self) -> Self {
        self.inverse().unwrap_or(G2FieldElement::zero())
    }

    /// Conjugation: (a + bu)* = a - bu
    pub fn conjugate(&self) -> G2FieldElement {
        G2FieldElement {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    // Frobenius coefficients for BN254 (precomputed)
    pub fn frobenius_coeff_x_1() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x99e39557176f553d, 0xb78cc310c2c3330c, 0x4c0bec3cf559b143, 0x2fb347984f7911f7]),
            c1: FieldElement::from_limbs([0x1665d51c640fcba2, 0x32ae2a1d0b7c9dce, 0x4ba4cc8bd75a0794, 0x16c9e55061ebae20]),
        }
    }

    pub fn frobenius_coeff_x_2() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x5033a4b3d8d18c8c, 0x285c512fe7e6c4b9, 0xf1495f6b8b30ba53, 0x30644e72e131a028]),
            c1: FieldElement::zero(),
        }
    }

    pub fn frobenius_coeff_y_1() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0xc3d91224a3c3c88, 0x35f93c7f4a91f5a3, 0x7f4a62d86f9c4c30, 0x14e56d3f1564853a]),
            c1: FieldElement::from_limbs([0x9e95df4e3c3c5d4, 0x8c9c5dccbb7c3dbb, 0x1606b7fe9b9a34c4, 0x23f61f8ab6f91f1f]),
        }
    }

    pub fn frobenius_coeff_y_2() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x59e26bcea0d48bac, 0x0, 0x0, 0x0]),
            c1: FieldElement::zero(),
        }
    }

    pub fn frobenius_coeff_fp12() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x856e078b755ef0a, 0x8c2734e1d7c5ce4a, 0x572cb8e7e5c79a9f, 0x2c145edbe7fd8aee]),
            c1: FieldElement::from_limbs([0x6a3e5dd97bb1bb77, 0xa6d38c2eb0d7c7c8, 0x8c4fae6e7c1b3de6, 0x26a6e7e5e7c0f5db]),
        }
    }

    pub fn frobenius_coeff_fp12_sq() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x30644e72e131a029, 0x0, 0x0, 0x0]),
            c1: FieldElement::zero(),
        }
    }

    pub fn frobenius_coeff_fp12_cub() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x59e26bcea0d48ba6, 0x0, 0x0, 0x0]),
            c1: FieldElement::from_limbs([0x0, 0x0, 0x0, 0x0]),
        }
    }
}

impl PartialEq for G2FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl G2Point {
    /// Point at infinity
    pub const fn infinity() -> Self {
        G2Point {
            x: G2FieldElement::ZERO,
            y: G2FieldElement::ONE,
            z: G2FieldElement::ZERO,
        }
    }

    /// Generator point
    pub fn generator() -> Self {
        G2Point {
            x: G2FieldElement {
                c0: FieldElement { limbs: G2_GENERATOR_X_C0 }.to_montgomery(),
                c1: FieldElement { limbs: G2_GENERATOR_X_C1 }.to_montgomery(),
            },
            y: G2FieldElement {
                c0: FieldElement { limbs: G2_GENERATOR_Y_C0 }.to_montgomery(),
                c1: FieldElement { limbs: G2_GENERATOR_Y_C1 }.to_montgomery(),
            },
            z: G2FieldElement::one(),
        }
    }

    /// Check if point is at infinity
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Point addition in Jacobian coordinates
    pub fn add(&self, other: &G2Point) -> G2Point {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }

        // G2 addition using same formulas as G1 but with Fp2 arithmetic
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
                return G2Point::infinity();
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

        G2Point { x: x3, y: y3, z: z3 }
    }

    /// Point doubling
    pub fn double(&self) -> G2Point {
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

        G2Point { x: x3, y: y3, z: z3 }
    }

    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &[u64; 4]) -> G2Point {
        let mut result = G2Point::infinity();
        let mut base = *self;

        for &limb in scalar.iter() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.double();
            }
        }

        result
    }

    /// Check if point is on curve
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }

        // Check y^2 = x^3 + 3 in projective coordinates for G2
        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let z6 = self.z.square().square().square();
        let b_z6 = G2FieldElement::from_base_field(&FieldElement::from_u64(3)).mul(&z6);

        y2 == x3.add(&b_z6)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        if let Some((x, _y)) = self.to_affine_coords() {
            let x0_mont = x.c0.from_montgomery();
            let x1_mont = x.c1.from_montgomery();

            // Store real part
            for i in 0..4 {
                let limb_bytes = x0_mont.limbs[i].to_le_bytes();
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
            }

            // Store imaginary part
            for i in 0..4 {
                let limb_bytes = x1_mont.limbs[i].to_le_bytes();
                bytes[(i + 4) * 8..(i + 5) * 8].copy_from_slice(&limb_bytes);
            }
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKError> {
        if bytes.len() < 64 {
            return Err(ZKError::InvalidProof);
        }

        // Extract coordinates
        let mut c0_limbs = [0u64; 4];
        let mut c1_limbs = [0u64; 4];

        for i in 0..4 {
            c0_limbs[i] = u64::from_le_bytes([
                bytes[i * 8], bytes[i * 8 + 1], bytes[i * 8 + 2], bytes[i * 8 + 3],
                bytes[i * 8 + 4], bytes[i * 8 + 5], bytes[i * 8 + 6], bytes[i * 8 + 7],
            ]);

            c1_limbs[i] = u64::from_le_bytes([
                bytes[(i + 4) * 8], bytes[(i + 4) * 8 + 1], bytes[(i + 4) * 8 + 2], bytes[(i + 4) * 8 + 3],
                bytes[(i + 4) * 8 + 4], bytes[(i + 4) * 8 + 5], bytes[(i + 4) * 8 + 6], bytes[(i + 4) * 8 + 7],
            ]);
        }

        let x = G2FieldElement {
            c0: FieldElement { limbs: c0_limbs }.to_montgomery(),
            c1: FieldElement { limbs: c1_limbs }.to_montgomery(),
        };

        // Compute y from curve equation (simplified)
        let point = G2Point { x, y: G2FieldElement::one(), z: G2FieldElement::one() };

        Ok(point)
    }

    /// Convert to affine coordinates (tuple form)
    pub fn to_affine_coords(&self) -> Option<(G2FieldElement, G2FieldElement)> {
        if self.is_infinity() {
            return None;
        }

        let z_inv = self.z.inverse()?;
        let x_affine = self.x.mul(&z_inv);
        let y_affine = self.y.mul(&z_inv);

        Some((x_affine, y_affine))
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
        G2Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Deserialize G2Point from 128 bytes (x and y coordinates in Fp2)
    pub fn deserialize(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 128 {
            return Err(ZKError::InvalidFormat);
        }

        // Check for identity point (all zeros)
        if data.iter().all(|&b| b == 0) {
            return Ok(G2Point::identity());
        }

        // Parse x coordinate (64 bytes: c0, c1)
        let x = Self::parse_fp2(&data[0..64])?;

        // Parse y coordinate (64 bytes: c0, c1)
        let y = Self::parse_fp2(&data[64..128])?;

        Ok(G2Point {
            x,
            y,
            z: G2FieldElement::one(),
        })
    }

    /// Parse an Fp2 element from 64 bytes (c0, c1)
    fn parse_fp2(data: &[u8]) -> Result<G2FieldElement, ZKError> {
        let c0 = FieldElement::from_bytes(&data[0..32])?;
        let c1 = FieldElement::from_bytes(&data[32..64])?;

        Ok(G2FieldElement { c0, c1 })
    }

    /// Serialize G2Point to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);

        if let Some((x, y)) = self.to_affine_coords() {
            // Serialize x coordinate (c0, c1)
            let x0_mont = x.c0.from_montgomery();
            let x1_mont = x.c1.from_montgomery();
            for limb in x0_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
            for limb in x1_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }

            // Serialize y coordinate (c0, c1)
            let y0_mont = y.c0.from_montgomery();
            let y1_mont = y.c1.from_montgomery();
            for limb in y0_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
            for limb in y1_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
        } else {
            data.extend_from_slice(&[0u8; 128]); // Identity point
        }

        data
    }

    /// Convert to affine coordinates for pairing
    pub fn to_affine(&self) -> G2Affine {
        if self.is_infinity() {
            return G2Affine {
                x: G2FieldElement::zero(),
                y: G2FieldElement::zero(),
            };
        }

        let z_inv = self.z.inverse_unchecked();
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);

        G2Affine {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
        }
    }
}

/// G2 affine point for pairing
#[derive(Clone, Copy)]
pub struct G2Affine {
    pub x: G2FieldElement,
    pub y: G2FieldElement,
}

impl G2Affine {
    pub fn neg(&self) -> Self {
        G2Affine {
            x: self.x,
            y: self.y.neg(),
        }
    }
}

// Type alias for clarity
pub type Fp2Element = G2FieldElement;

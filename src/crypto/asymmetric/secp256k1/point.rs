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

use super::field::FieldElement;
use super::scalar::Scalar;

#[derive(Clone, Copy)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub infinity: bool,
}

#[derive(Clone, Copy)]
pub struct ProjectivePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl AffinePoint {
    pub fn identity() -> Self {
        Self {
            x: FieldElement::ZERO,
            y: FieldElement::ZERO,
            infinity: true,
        }
    }

    pub fn generator() -> Self {
        Self {
            x: FieldElement([
                0x59F2815B16F81798, 0x029BFCDB2DCE28D9,
                0x55A06295CE870B07, 0x79BE667EF9DCBBAC
            ]),
            y: FieldElement([
                0x9C47D08FFB10D4B8, 0xFD17B448A6855419,
                0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465
            ]),
            infinity: false,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            33 => Self::from_compressed(bytes.try_into().ok()?),
            65 => Self::from_uncompressed(bytes.try_into().ok()?),
            _ => None,
        }
    }

    pub fn from_compressed(bytes: &[u8; 33]) -> Option<Self> {
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return None;
        }

        let x = FieldElement::from_bytes(bytes[1..33].try_into().ok()?)?;

        if x.0 == [0, 0, 0, 0] {
            return None;
        }

        let y_squared = x.mul(&x).mul(&x).add(&FieldElement([7, 0, 0, 0]));
        let y = y_squared.sqrt()?;

        let y = if (bytes[0] == 0x02) == y.is_even() {
            y
        } else {
            y.negate()
        };

        Some(Self { x, y, infinity: false })
    }

    pub fn from_uncompressed(bytes: &[u8; 65]) -> Option<Self> {
        if bytes[0] != 0x04 {
            return None;
        }

        let x = FieldElement::from_bytes(bytes[1..33].try_into().ok()?)?;
        let y = FieldElement::from_bytes(bytes[33..65].try_into().ok()?)?;

        if x.0 == [0, 0, 0, 0] && y.0 == [0, 0, 0, 0] {
            return None;
        }

        let y_squared = x.mul(&x).mul(&x).add(&FieldElement([7, 0, 0, 0]));
        if y.mul(&y) != y_squared {
            return None;
        }

        Some(Self { x, y, infinity: false })
    }

    pub fn to_uncompressed(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[1..33].copy_from_slice(&self.x.to_bytes());
        bytes[33..65].copy_from_slice(&self.y.to_bytes());
        bytes
    }

    pub fn to_compressed(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = if self.y.is_even() { 0x02 } else { 0x03 };
        bytes[1..33].copy_from_slice(&self.x.to_bytes());
        bytes
    }

    pub fn to_projective(&self) -> ProjectivePoint {
        if self.infinity {
            ProjectivePoint {
                x: FieldElement::ZERO,
                y: FieldElement::ONE,
                z: FieldElement::ZERO,
            }
        } else {
            ProjectivePoint {
                x: self.x,
                y: self.y,
                z: FieldElement::ONE,
            }
        }
    }
}

impl ProjectivePoint {
    pub fn identity() -> Self {
        Self {
            x: FieldElement::ZERO,
            y: FieldElement::ONE,
            z: FieldElement::ZERO,
        }
    }

    pub fn is_identity(&self) -> bool {
        self.z.0 == [0, 0, 0, 0]
    }

    pub fn double(&self) -> Self {
        // Constant-time doubling: compute result unconditionally, then select
        let xx = self.x.square();
        let yy = self.y.square();
        let yyyy = yy.square();
        let zz = self.z.square();

        let s = self.x.add(&yy).square().sub(&xx).sub(&yyyy);
        let s = s.add(&s);

        let m = xx.add(&xx).add(&xx);

        let t = m.square().sub(&s).sub(&s);

        let x3 = t;
        let y3 = m.mul(&s.sub(&t)).sub(&yyyy.add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy));
        let z3 = self.y.add(&self.z).square().sub(&yy).sub(&zz);

        let result = Self { x: x3, y: y3, z: z3 };

        // If self is identity, return identity; otherwise return computed result
        let is_id = self.z.ct_is_zero();
        Self::ct_select(is_id, self, &result)
    }

    pub fn add(&self, other: &Self) -> Self {
        // Constant-time addition: compute all branches and select result
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);

        let h = u2.sub(&u1);
        let i = h.add(&h).square();
        let j = h.mul(&i);
        let r = s2.sub(&s1).add(&s2.sub(&s1));
        let v = u1.mul(&i);

        let x3 = r.square().sub(&j).sub(&v).sub(&v);
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).add(&s1.mul(&j)));
        let z3 = self.z.add(&other.z).square().sub(&z1z1).sub(&z2z2).mul(&h);

        let add_result = Self { x: x3, y: y3, z: z3 };

        // Compute the double result for when points are equal
        let double_result = self.double();

        // Check conditions using constant-time operations
        let self_is_id = self.z.ct_is_zero();
        let other_is_id = other.z.ct_is_zero();
        let u_eq = u1.ct_eq(&u2);
        let s_eq = s1.ct_eq(&s2);

        // If self is identity, return other
        let mut result = Self::ct_select(self_is_id, other, &add_result);
        // If other is identity, return self
        result = Self::ct_select(other_is_id, self, &result);
        // If u1 == u2 and s1 == s2, return double
        result = Self::ct_select(u_eq & s_eq, &double_result, &result);
        // If u1 == u2 and s1 != s2, return identity
        let return_identity = u_eq & (1 ^ s_eq);
        result = Self::ct_select(return_identity, &Self::identity(), &result);

        result
    }

    fn ct_select(condition: u64, a: &Self, b: &Self) -> Self {
        let mask = 0u64.wrapping_sub(condition);
        Self {
            x: FieldElement::ct_select(mask, &a.x, &b.x),
            y: FieldElement::ct_select(mask, &a.y, &b.y),
            z: FieldElement::ct_select(mask, &a.z, &b.z),
        }
    }

    pub fn mul(&self, scalar: &Scalar) -> Self {
        let mut r0 = Self::identity();
        let mut r1 = *self;

        for i in (0..256).rev() {
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            let bit = (scalar.0[limb_idx] >> bit_idx) & 1;

            let sum = r0.add(&r1);
            let r0_double = r0.double();
            let r1_double = r1.double();

            r0 = Self::ct_select(bit, &r0_double, &sum);
            r1 = Self::ct_select(bit, &sum, &r1_double);
        }

        r0
    }

    pub fn to_affine(&self) -> AffinePoint {
        if self.is_identity() {
            return AffinePoint::identity();
        }

        let z_inv = match self.z.invert() {
            Some(inv) => inv,
            None => return AffinePoint::identity(),
        };
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);

        AffinePoint {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
            infinity: false,
        }
    }
}

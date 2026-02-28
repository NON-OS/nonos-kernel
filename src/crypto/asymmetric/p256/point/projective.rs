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

use super::super::{FieldElement, Scalar};
use super::types::{AffinePoint, ProjectivePoint};

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
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let yyyy = yy.square();

        let s = self.x.add(&yy).square().sub(&xx).sub(&yyyy);
        let s = s.add(&s);

        let zzzz = zz.square();
        let m = xx.add(&xx).add(&xx).sub(&zzzz.add(&zzzz).add(&zzzz));

        let t = m.square().sub(&s).sub(&s);

        let x3 = t.clone();
        let y3 = m.mul(&s.sub(&t)).sub(
            &yyyy.add(&yyyy).add(&yyyy).add(&yyyy)
                .add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy)
        );
        let z3 = self.y.add(&self.z).square().sub(&yy).sub(&zz);

        let result = Self { x: x3, y: y3, z: z3 };

        let is_id = self.z.ct_is_zero();
        Self::ct_select(is_id, self, &result)
    }

    pub fn add(&self, other: &Self) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);

        let h = u2.sub(&u1);
        let h2 = h.add(&h);
        let i = h2.square();
        let j = h.mul(&i);
        let s_diff = s2.sub(&s1);
        let r = s_diff.add(&s_diff);
        let v = u1.mul(&i);

        let r2 = r.square();
        let v2 = v.add(&v);
        let x3 = r2.sub(&j).sub(&v2);

        let v_minus_x3 = v.sub(&x3);
        let s1_j = s1.mul(&j);
        let s1_j_2 = s1_j.add(&s1_j);
        let y3 = r.mul(&v_minus_x3).sub(&s1_j_2);

        let z1_plus_z2 = self.z.add(&other.z);
        let z1_plus_z2_sq = z1_plus_z2.square();
        let z3 = z1_plus_z2_sq.sub(&z1z1).sub(&z2z2).mul(&h);

        let add_result = Self { x: x3, y: y3, z: z3 };

        let double_result = self.double();

        let self_is_id = self.z.ct_is_zero();
        let other_is_id = other.z.ct_is_zero();
        let h_is_zero = h.ct_is_zero();
        let s_diff_is_zero = s_diff.ct_is_zero();

        let mut result = Self::ct_select(self_is_id, other, &add_result);
        result = Self::ct_select(other_is_id, self, &result);
        result = Self::ct_select(h_is_zero & s_diff_is_zero, &double_result, &result);
        let return_identity = h_is_zero & (1 ^ s_diff_is_zero);
        result = Self::ct_select(return_identity, &Self::identity(), &result);

        result
    }

    pub fn ct_select(mask: u64, a: &Self, b: &Self) -> Self {
        Self {
            x: FieldElement::ct_select(mask, &a.x, &b.x),
            y: FieldElement::ct_select(mask, &a.y, &b.y),
            z: FieldElement::ct_select(mask, &a.z, &b.z),
        }
    }

    pub fn mul(&self, scalar: &Scalar) -> Self {
        let mut r0 = Self::identity();
        let mut r1 = self.clone();

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

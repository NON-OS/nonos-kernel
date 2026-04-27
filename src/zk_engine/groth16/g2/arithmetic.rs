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

use super::point::G2Point;

impl G2Point {
    pub fn add(&self, other: &G2Point) -> G2Point {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
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
}

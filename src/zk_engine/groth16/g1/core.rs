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

use super::super::field::FieldElement;
use super::types::{G1Point, G1_GENERATOR_X, G1_GENERATOR_Y};

impl G1Point {
    pub const fn infinity() -> Self {
        G1Point { x: FieldElement::ZERO, y: FieldElement::ONE, z: FieldElement::ZERO }
    }

    pub fn generator() -> Self {
        G1Point {
            x: FieldElement { limbs: G1_GENERATOR_X }.to_montgomery(),
            y: FieldElement { limbs: G1_GENERATOR_Y }.to_montgomery(),
            z: FieldElement::one(),
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    pub fn neg(&self) -> G1Point {
        G1Point { x: self.x, y: self.y.neg(), z: self.z }
    }
    pub fn negate(&self) -> Self {
        G1Point { x: self.x, y: self.y.neg(), z: self.z }
    }

    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }
        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let z6 = self.z.square().square().square();
        let b_z6 = FieldElement::from_u64(3).mul(&z6);
        y2 == x3.add(&b_z6)
    }

    pub fn identity() -> Self {
        Self::infinity()
    }
    pub fn is_identity(&self) -> bool {
        self.is_infinity()
    }
    pub fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        G1Point { x, y, z: FieldElement::one() }
    }
}

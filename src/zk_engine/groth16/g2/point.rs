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

use super::affine::G2Affine;
use super::consts::*;
use super::field_element::G2FieldElement;
use crate::zk_engine::groth16::field::FieldElement;

#[derive(Debug, Clone, Copy)]
pub struct G2Point {
    pub x: G2FieldElement,
    pub y: G2FieldElement,
    pub z: G2FieldElement,
}

impl G2Point {
    pub const fn infinity() -> Self {
        G2Point { x: G2FieldElement::ZERO, y: G2FieldElement::ONE, z: G2FieldElement::ZERO }
    }
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
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }
    pub fn identity() -> Self {
        Self::infinity()
    }
    pub fn is_identity(&self) -> bool {
        self.is_infinity()
    }
    pub fn negate(&self) -> Self {
        G2Point { x: self.x, y: self.y.neg(), z: self.z }
    }
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }
        let y2 = self.y.square();
        let x3 = self.x.square().mul(&self.x);
        let z6 = self.z.square().square().square();
        let b_z6 = G2FieldElement::from_base_field(&FieldElement::from_u64(3)).mul(&z6);
        y2 == x3.add(&b_z6)
    }
    pub fn to_affine_coords(&self) -> Option<(G2FieldElement, G2FieldElement)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.inverse()?;
        Some((self.x.mul(&z_inv), self.y.mul(&z_inv)))
    }
    pub fn to_affine(&self) -> G2Affine {
        if self.is_infinity() {
            return G2Affine { x: G2FieldElement::zero(), y: G2FieldElement::zero() };
        }
        let z_inv = self.z.inverse_unchecked();
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);
        G2Affine { x: self.x.mul(&z_inv2), y: self.y.mul(&z_inv3) }
    }
}

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

#[derive(Debug, Clone, Copy)]
pub struct G2FieldElement {
    pub c0: FieldElement,
    pub c1: FieldElement,
}

impl G2FieldElement {
    pub const ZERO: Self = G2FieldElement { c0: FieldElement::ZERO, c1: FieldElement::ZERO };
    pub const ONE: Self = G2FieldElement { c0: FieldElement::ONE, c1: FieldElement::ZERO };
    pub const fn zero() -> Self {
        Self::ZERO
    }
    pub const fn one() -> Self {
        Self::ONE
    }
    pub fn from_base_field(base: &FieldElement) -> Self {
        G2FieldElement { c0: *base, c1: FieldElement::zero() }
    }
    pub fn from_base(e: FieldElement) -> Self {
        G2FieldElement { c0: e, c1: FieldElement::zero() }
    }
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }
    pub fn add(&self, other: &G2FieldElement) -> G2FieldElement {
        G2FieldElement { c0: self.c0.add(&other.c0), c1: self.c1.add(&other.c1) }
    }
    pub fn sub(&self, other: &G2FieldElement) -> G2FieldElement {
        G2FieldElement { c0: self.c0.sub(&other.c0), c1: self.c1.sub(&other.c1) }
    }
    pub fn mul(&self, other: &G2FieldElement) -> G2FieldElement {
        let v0 = self.c0.mul(&other.c0);
        let v1 = self.c1.mul(&other.c1);
        let v2 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1));
        G2FieldElement { c0: v0.sub(&v1), c1: v2.sub(&v0).sub(&v1) }
    }
    pub fn square(&self) -> G2FieldElement {
        let a_squared = self.c0.square();
        let b_squared = self.c1.square();
        let two_ab = self.c0.mul(&self.c1).double();
        G2FieldElement { c0: a_squared.sub(&b_squared), c1: two_ab }
    }
    pub fn double(&self) -> G2FieldElement {
        self.add(self)
    }
    pub fn neg(&self) -> G2FieldElement {
        G2FieldElement { c0: self.c0.neg(), c1: self.c1.neg() }
    }
    pub fn inverse(&self) -> Option<G2FieldElement> {
        if self.is_zero() {
            return None;
        }
        let a_squared = self.c0.square();
        let b_squared = self.c1.square();
        let norm = a_squared.add(&b_squared);
        let norm_inv = norm.inverse()?;
        Some(G2FieldElement { c0: self.c0.mul(&norm_inv), c1: self.c1.neg().mul(&norm_inv) })
    }
    pub fn inverse_unchecked(&self) -> Self {
        self.inverse().unwrap_or(G2FieldElement::zero())
    }
    pub fn conjugate(&self) -> G2FieldElement {
        G2FieldElement { c0: self.c0, c1: self.c1.neg() }
    }
}

impl PartialEq for G2FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

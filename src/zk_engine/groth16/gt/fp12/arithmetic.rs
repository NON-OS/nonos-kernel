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

use super::core::GTElement;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::g2::G2FieldElement;
use crate::zk_engine::groth16::gt::fp6::Fp6Element;

impl GTElement {
    pub fn mul(&self, other: &GTElement) -> GTElement {
        let ac = self.c0.mul(&other.c0);
        let bd = self.c1.mul(&other.c1);
        let ad = self.c0.mul(&other.c1);
        let bc = self.c1.mul(&other.c0);
        GTElement { c0: ac.add(&bd.mul_by_nonresidue()), c1: ad.add(&bc) }
    }

    pub fn multiply(&self, other: &GTElement) -> GTElement {
        self.mul(other)
    }

    pub fn square(&self) -> GTElement {
        let a = self.c0.add(&self.c1);
        let b = self.c0.sub(&self.c1);
        let c = self.c0.mul(&self.c1);
        let two = Fp6Element::from_fp2(G2FieldElement::from_base(FieldElement::from_u64(2)));
        GTElement { c0: a.mul(&b).add(&c), c1: two.mul(&c) }
    }

    pub fn inverse(&self) -> GTElement {
        let c0_sq = self.c0.square();
        let c1_sq = self.c1.square();
        let v = c0_sq.sub(&c1_sq.mul_by_nonresidue());
        let v_inv = v.inverse();
        GTElement { c0: self.c0.mul(&v_inv), c1: self.c1.neg().mul(&v_inv) }
    }

    pub fn inverse_unchecked(&self) -> GTElement {
        self.inverse()
    }

    pub fn conjugate(&self) -> GTElement {
        GTElement { c0: self.c0, c1: self.c1.neg() }
    }
}

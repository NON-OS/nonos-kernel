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

use super::core::Fp6Element;

impl Fp6Element {
    pub fn add(&self, other: &Self) -> Self {
        Fp6Element {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
            c2: self.c2.add(&other.c2),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Fp6Element {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
            c2: self.c2.sub(&other.c2),
        }
    }

    pub fn neg(&self) -> Self {
        Fp6Element { c0: self.c0.neg(), c1: self.c1.neg(), c2: self.c2.neg() }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let a0b0 = self.c0.mul(&other.c0);
        let a1b1 = self.c1.mul(&other.c1);
        let a2b2 = self.c2.mul(&other.c2);
        let c0 = a0b0.add(&Self::mul_by_nonresidue_fp2(&a1b1.add(&a2b2)));
        let c1 = self
            .c0
            .add(&self.c1)
            .mul(&other.c0.add(&other.c1))
            .sub(&a0b0)
            .sub(&a1b1)
            .add(&Self::mul_by_nonresidue_fp2(&a2b2));
        let c2 =
            self.c0.add(&self.c2).mul(&other.c0.add(&other.c2)).sub(&a0b0).add(&a1b1).sub(&a2b2);
        Fp6Element { c0, c1, c2 }
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }
}

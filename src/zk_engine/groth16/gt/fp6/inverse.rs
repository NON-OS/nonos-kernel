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
    pub fn inverse(&self) -> Self {
        let c0_sq = self.c0.square();
        let c1_sq = self.c1.square();
        let c2_sq = self.c2.square();
        let c0c1 = self.c0.mul(&self.c1);
        let c0c2 = self.c0.mul(&self.c2);
        let c1c2 = self.c1.mul(&self.c2);
        let t0 = c0_sq.sub(&Self::mul_by_nonresidue_fp2(&c1c2));
        let t1 = Self::mul_by_nonresidue_fp2(&c2_sq).sub(&c0c1);
        let t2 = c1_sq.sub(&c0c2);
        let inv_norm = self
            .c0
            .mul(&t0)
            .add(&Self::mul_by_nonresidue_fp2(&self.c2.mul(&t1).add(&self.c1.mul(&t2))))
            .inverse_unchecked();
        Fp6Element { c0: t0.mul(&inv_norm), c1: t1.mul(&inv_norm), c2: t2.mul(&inv_norm) }
    }
}

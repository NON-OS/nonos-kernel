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

use super::super::SQRT_M1;
use super::types::FieldElement;

impl FieldElement {
    pub fn invert(&self) -> FieldElement {
        let z1 = self.clone();
        let z2 = z1.square();
        let z4 = z2.square();
        let z8 = z4.square();
        let z9 = z8.mul(&z1);
        let z11 = z9.mul(&z2);
        let z22 = z11.square();
        let z_5_0 = z22.mul(&z9);

        let mut t = z_5_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        let z_10_0 = t.mul(&z_5_0);

        let mut t = z_10_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_20_0 = t.mul(&z_10_0);

        let mut t = z_20_0.square();
        for _ in 1..20 {
            t = t.square();
        }
        let z_40_0 = t.mul(&z_20_0);

        let mut t = z_40_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_50_0 = t.mul(&z_10_0);

        let mut t = z_50_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_100_0 = t.mul(&z_50_0);

        let mut t = z_100_0.square();
        for _ in 1..100 {
            t = t.square();
        }
        let z_200_0 = t.mul(&z_100_0);

        let mut t = z_200_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_250_0 = t.mul(&z_50_0);

        let mut t = z_250_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        t.mul(&z11)
    }

    pub fn sqrt(&self) -> Option<FieldElement> {
        let z1 = self.clone();
        let z2 = z1.square();
        let z4 = z2.square();
        let z8 = z4.square();
        let z9 = z8.mul(&z1);
        let z11 = z9.mul(&z2);
        let z22 = z11.square();
        let z_5_0 = z22.mul(&z9);

        let mut t = z_5_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        let z_10_0 = t.mul(&z_5_0);

        let mut t = z_10_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_20_0 = t.mul(&z_10_0);

        let mut t = z_20_0.square();
        for _ in 1..20 {
            t = t.square();
        }
        let z_40_0 = t.mul(&z_20_0);

        let mut t = z_40_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_50_0 = t.mul(&z_10_0);

        let mut t = z_50_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_100_0 = t.mul(&z_50_0);

        let mut t = z_100_0.square();
        for _ in 1..100 {
            t = t.square();
        }
        let z_200_0 = t.mul(&z_100_0);

        let mut t = z_200_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_250_0 = t.mul(&z_50_0);

        let mut t = z_250_0.square();
        t = t.square();
        let beta = t.mul(&z2);

        let beta_sq = beta.square();
        if beta_sq.ct_eq(self) {
            return Some(beta);
        }

        let sqrt_m1 = SQRT_M1;
        let beta_i = beta.mul(&sqrt_m1);
        let beta_i_sq = beta_i.square();
        if beta_i_sq.ct_eq(self) {
            return Some(beta_i);
        }

        None
    }
}

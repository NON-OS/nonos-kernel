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

const BN_X: u64 = 4965661367192848881;

impl GTElement {
    pub fn final_exponentiation(&self) -> GTElement {
        let f = self.easy_part();
        f.hard_part()
    }

    fn easy_part(&self) -> GTElement {
        let f1 = self.conjugate();
        let f2 = self.inverse();
        let f = f1.mul(&f2);
        f.frobenius_square().mul(&f)
    }

    fn hard_part(&self) -> GTElement {
        let y0 = self.square();
        let y1 = y0.exp_by_x(BN_X);
        let y2 = y1.exp_by_x(BN_X);
        let y3 = y2.exp_by_x(BN_X);
        let y4 = y3.exp_by_x(BN_X);
        let y5 = y4.exp_by_x(BN_X);
        let y6 = y5.exp_by_x(BN_X);
        let y1 = y1.conjugate();
        let y3 = y3.conjugate();
        let y4 = y4.mul(&y5.conjugate());
        let y6 = y6.conjugate();
        let t0 = y6.square().mul(&y4).mul(&y5);
        let t1 = y3.mul(&y5).mul(&t0);
        let t0 = t0.mul(&y2);
        let t1 = t1.square().mul(&t0).square();
        let t0 = t1.mul(&y1);
        let t1 = t1.mul(&y0);
        t0.square().mul(&t1)
    }

    pub fn exp_by_x(&self, x: u64) -> GTElement {
        let mut result = GTElement::one();
        let mut base = *self;
        let mut exp = x;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();
            exp >>= 1;
        }
        result
    }
}

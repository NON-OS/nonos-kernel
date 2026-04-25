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

use super::BN254_X;
use crate::zk_engine::groth16::gt::GTElement;

pub(super) fn final_exponentiation(f: &GTElement) -> GTElement {
    let f1 = f.conjugate();
    let f2 = f.inverse_unchecked();
    let f3 = f1.mul(&f2);

    let f4 = f3.frobenius_square().mul(&f3);

    final_exp_hard_part(&f4)
}

fn final_exp_hard_part(f: &GTElement) -> GTElement {
    let x = BN254_X;

    let fx = f.exp_by_x(x);
    let fxx = fx.exp_by_x(x);
    let fxxx = fxx.exp_by_x(x);

    let fp = f.frobenius();
    let fpp = f.frobenius_square();
    let fppp = f.frobenius_cube();

    let t0 = fpp.mul(&fxxx);
    let t1 = fx.conjugate();
    let t2 = fppp.mul(&t1);
    let t3 = t0.mul(&t2);
    let t4 = fxx.conjugate();
    let t5 = fp.mul(&t4);
    let t6 = t3.mul(&t5);
    let result = t6.mul(f);

    result
}

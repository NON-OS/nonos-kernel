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

use super::line::LineFunctionCoeffs;
use crate::zk_engine::groth16::gt::{Fp6Element, GTElement};

pub(super) fn mul_by_line_evaluation(f: &GTElement, line: &LineFunctionCoeffs) -> GTElement {
    let c0 = Fp6Element {
        c0: f.c0.c0.mul(&line.l0),
        c1: f.c0.c1.mul(&line.l1),
        c2: f.c0.c2.mul(&line.l2),
    };

    let c1 = Fp6Element {
        c0: f.c1.c0.mul(&line.l0),
        c1: f.c1.c1.mul(&line.l1),
        c2: f.c1.c2.mul(&line.l2),
    };

    GTElement { c0, c1 }
}

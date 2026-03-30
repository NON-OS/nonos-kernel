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

use crate::zk_engine::groth16::g1::G1Affine;
use crate::zk_engine::groth16::g2::{G2Affine, G2FieldElement};

pub(super) struct LineFunctionCoeffs {
    pub l0: G2FieldElement,
    pub l1: G2FieldElement,
    pub l2: G2FieldElement,
}

pub(super) fn line_double(r: &mut G2Affine, p: &G1Affine) -> LineFunctionCoeffs {
    let x_sq = r.x.square();
    let three_x_sq = x_sq.add(&x_sq).add(&x_sq);
    let two_y = r.y.double();
    let lambda = three_x_sq.mul(&two_y.inverse_unchecked());

    let x_new = lambda.square().sub(&r.x.double());
    let y_new = lambda.mul(&r.x.sub(&x_new)).sub(&r.y);

    let line = LineFunctionCoeffs {
        l0: lambda.neg(),
        l1: G2FieldElement::from_base(p.x),
        l2: G2FieldElement::from_base(p.y.neg()),
    };

    r.x = x_new;
    r.y = y_new;

    line
}

pub(super) fn line_add(r: &mut G2Affine, q: &G2Affine, p: &G1Affine) -> LineFunctionCoeffs {
    let delta_y = q.y.sub(&r.y);
    let delta_x = q.x.sub(&r.x);
    let lambda = delta_y.mul(&delta_x.inverse_unchecked());

    let x_new = lambda.square().sub(&r.x).sub(&q.x);
    let y_new = lambda.mul(&r.x.sub(&x_new)).sub(&r.y);

    let line = LineFunctionCoeffs {
        l0: lambda.neg(),
        l1: G2FieldElement::from_base(p.x),
        l2: G2FieldElement::from_base(p.y.neg()),
    };

    r.x = x_new;
    r.y = y_new;

    line
}

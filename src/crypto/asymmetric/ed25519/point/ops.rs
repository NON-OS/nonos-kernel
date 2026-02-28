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

use crate::crypto::asymmetric::ed25519::field::{
    fe_add, fe_copy, fe_mul, fe_sq, fe_sub, Fe,
};
use super::types::{GeP3, GeP2, GeCached, GeP1P1, D2};

#[inline]
pub(crate) fn ge_identity() -> GeP3 {
    GeP3 {
        X: Fe::zero(),
        Y: Fe::one(),
        Z: Fe::one(),
        T: Fe::zero(),
    }
}

#[inline]
pub(crate) fn ge_to_cached(p: &GeP3) -> GeCached {
    GeCached {
        YplusX: fe_add(&p.Y, &p.X),
        YminusX: fe_sub(&p.Y, &p.X),
        Z: fe_copy(&p.Z),
        T2d: fe_mul(&p.T, &D2),
    }
}

pub(crate) fn ge_add(p: &GeP3, q: &GeCached) -> GeP1P1 {
    let YplusX = fe_add(&p.Y, &p.X);
    let YminusX = fe_sub(&p.Y, &p.X);
    let PP = fe_mul(&YplusX, &q.YplusX);
    let MM = fe_mul(&YminusX, &q.YminusX);
    let TT2d = fe_mul(&p.T, &q.T2d);
    let ZZ = fe_mul(&p.Z, &q.Z);
    let ZZ2 = fe_add(&ZZ, &ZZ);
    GeP1P1 {
        X: fe_sub(&PP, &MM),
        Y: fe_add(&PP, &MM),
        Z: fe_add(&ZZ2, &TT2d),
        T: fe_sub(&ZZ2, &TT2d),
    }
}

pub(crate) fn ge_double(p: &GeP2) -> GeP1P1 {
    let XX = fe_sq(&p.X);
    let YY = fe_sq(&p.Y);
    let ZZ2 = fe_add(&fe_sq(&p.Z), &fe_sq(&p.Z));
    let XpY = fe_add(&p.X, &p.Y);
    let XpY2 = fe_sq(&XpY);
    let YYpXX = fe_add(&YY, &XX);
    let YYmXX = fe_sub(&YY, &XX);
    let E = fe_sub(&XpY2, &YYpXX);
    let F = fe_sub(&ZZ2, &YYmXX);
    GeP1P1 {
        X: E,
        Y: YYpXX,
        Z: YYmXX,
        T: F,
    }
}

#[inline]
pub(crate) fn ge_p1p1_to_p3(r: &GeP1P1) -> GeP3 {
    let X = fe_mul(&r.X, &r.T);
    let Y = fe_mul(&r.Y, &r.Z);
    let Z = fe_mul(&r.Z, &r.T);
    let T = fe_mul(&r.X, &r.Y);
    GeP3 { X, Y, Z, T }
}

#[inline]
pub(crate) fn ge_p1p1_to_p2(r: &GeP1P1) -> GeP2 {
    let X = fe_mul(&r.X, &r.T);
    let Y = fe_mul(&r.Y, &r.Z);
    let Z = fe_mul(&r.Z, &r.T);
    GeP2 { X, Y, Z }
}

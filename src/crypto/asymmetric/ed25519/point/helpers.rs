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

use super::ops::{ge_add, ge_double, ge_p1p1_to_p2, ge_p1p1_to_p3, ge_to_cached};
use super::pack::ge_basepoint;
use super::precomp::{ensure_precomp, Precomp, PRECOMP};
use super::scalarmult::{ct_byte_mask, ge_cmov, ge_scalarmult_base_ct, ge_scalarmult_ct};
use super::types::{Fe, GeCached, GeP1P1, GeP2, GeP3, D, D2};

pub(crate) fn double_scalar_mult(a: &[u8; 32], point_a: &GeP3, b: &[u8; 32]) -> GeP3 {
    let base_result = ge_scalarmult_base_ct(b);
    let point_result = ge_scalarmult_ct(point_a, a);
    let base_cached = ge_to_cached(&base_result);
    let sum_p1p1 = ge_add(&point_result, &base_cached);
    ge_p1p1_to_p3(&sum_p1p1)
}

pub(crate) fn point_double(p: &GeP3) -> GeP3 {
    let p1p1 = ge_double(&p.to_p2());
    ge_p1p1_to_p3(&p1p1)
}

pub(crate) fn get_basepoint() -> GeP3 {
    ge_basepoint()
}

pub(crate) fn get_curve_constants() -> (Fe, Fe) {
    (D, D2)
}

pub(crate) fn precompute_table() -> Option<&'static Precomp> {
    ensure_precomp();
    PRECOMP.get()
}

pub(crate) fn conditional_select(flag: u8, a: &GeP3, b: &GeP3) -> GeP3 {
    let mask = ct_byte_mask(flag);
    ge_cmov(a, b, mask)
}

pub(crate) fn convert_p1p1_to_p2(p: &GeP1P1) -> GeP2 {
    ge_p1p1_to_p2(p)
}

pub(crate) fn new_cached() -> GeCached {
    GeCached::identity()
}

pub(crate) fn new_p2_identity() -> GeP2 {
    GeP2::identity()
}

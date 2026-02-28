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

use crate::crypto::asymmetric::ed25519::field::{fe_cmov, fe_equal, fe_is_zero};
use super::types::{GeP3, GeP2};
use super::ops::{ge_identity, ge_to_cached, ge_add, ge_double, ge_p1p1_to_p3};
use super::pack::ge_basepoint;
use super::precomp::PRECOMP;

pub(crate) fn ge_scalarmult_base_ct(a: &[u8; 32]) -> GeP3 {
    let _ = PRECOMP.wait();
    ge_scalarmult_ct(&ge_basepoint(), a)
}

pub(crate) fn ge_scalarmult_ct(P: &GeP3, scalar: &[u8; 32]) -> GeP3 {
    let mut result = ge_identity();
    let mut temp = *P;

    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (scalar[byte_idx] >> bit_idx) & 1;

        let sum = ge_add(&result, &ge_to_cached(&temp));
        let sum_p3 = ge_p1p1_to_p3(&sum);

        let mask = ct_byte_mask(bit);
        result = ge_cmov(&result, &sum_p3, mask);

        let p2 = GeP2 {
            X: temp.X,
            Y: temp.Y,
            Z: temp.Z,
        };
        let doubled = ge_double(&p2);
        temp = ge_p1p1_to_p3(&doubled);
    }

    result
}

#[inline]
pub(crate) fn ct_byte_mask(bit: u8) -> u8 {
    0u8.wrapping_sub(bit)
}

#[inline]
pub(crate) fn ge_cmov(a: &GeP3, b: &GeP3, mask: u8) -> GeP3 {
    GeP3 {
        X: fe_cmov(&a.X, &b.X, mask),
        Y: fe_cmov(&a.Y, &b.Y, mask),
        Z: fe_cmov(&a.Z, &b.Z, mask),
        T: fe_cmov(&a.T, &b.T, mask),
    }
}

pub(crate) fn ge_scalarmult_vartime(P: &GeP3, scalar: &[u8; 32]) -> GeP3 {
    let mut result = ge_identity();
    let mut temp = *P;

    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (scalar[byte_idx] >> bit_idx) & 1;

        if bit == 1 {
            let sum = ge_add(&result, &ge_to_cached(&temp));
            result = ge_p1p1_to_p3(&sum);
        }

        let p2 = GeP2 {
            X: temp.X,
            Y: temp.Y,
            Z: temp.Z,
        };
        let doubled = ge_double(&p2);
        temp = ge_p1p1_to_p3(&doubled);
    }

    result
}

pub(crate) fn ge_scalarmult_point(P: &GeP3, s: &[u8; 32]) -> GeP3 {
    ge_scalarmult_vartime(P, s)
}

pub(crate) fn ge_has_large_order(p: &GeP3) -> bool {
    let p2 = ge_p1p1_to_p3(&ge_double(&GeP2 {
        X: p.X,
        Y: p.Y,
        Z: p.Z,
    }));
    let p4 = ge_p1p1_to_p3(&ge_double(&GeP2 {
        X: p2.X,
        Y: p2.Y,
        Z: p2.Z,
    }));
    let p8 = ge_p1p1_to_p3(&ge_double(&GeP2 {
        X: p4.X,
        Y: p4.Y,
        Z: p4.Z,
    }));

    let x_is_zero = fe_is_zero(&p8.X);
    let y_eq_z = fe_equal(&p8.Y, &p8.Z);

    !(x_is_zero && y_eq_z)
}

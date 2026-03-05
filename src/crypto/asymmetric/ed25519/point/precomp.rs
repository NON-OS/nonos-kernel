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

use spin::Once;
use super::types::{GeP2, GeCached};
use super::ops::{ge_to_cached, ge_add, ge_double, ge_p1p1_to_p3, ge_p1p1_to_p2};
use super::pack::ge_basepoint;

pub(crate) struct Precomp {
    _table: [[GeCached; 8]; 32],
}

pub(crate) static PRECOMP: Once<Precomp> = Once::new();

pub(crate) fn ensure_precomp() {
    PRECOMP.call_once(|| build_precomp());
}

fn build_precomp() -> Precomp {
    let B = ge_basepoint();
    let mut P = B;
    let mut table = [[GeCached::identity(); 8]; 32];
    for i in 0..32 {
        let P2 = ge_p1p1_to_p3(&ge_double(&GeP2 {
            X: P.X,
            Y: P.Y,
            Z: P.Z,
        }));
        let mut curr = P;
        for j in 0..8 {
            table[i][j] = ge_to_cached(&curr);
            let sum = ge_add(&curr, &ge_to_cached(&P2));
            curr = ge_p1p1_to_p3(&sum);
        }
        let mut p2 = GeP2 {
            X: P.X,
            Y: P.Y,
            Z: P.Z,
        };
        for _ in 0..8 {
            p2 = ge_p1p1_to_p2(&ge_double(&p2));
        }
        P = ge_p1p1_to_p3(&ge_double(&p2));
    }
    Precomp { _table: table }
}

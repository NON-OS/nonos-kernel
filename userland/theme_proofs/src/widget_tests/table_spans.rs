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

//! Table: the column mixes the width proof shares out, and the widths it
//! reads back from header hits.

use nonos_toolkit::design::scale::scale;
use nonos_toolkit::widgets::{Cell, Col, Rect, Table};

/// A column's width: fixed, in logical pixels, or a share.
#[derive(Clone, Copy, Debug)]
pub(crate) enum W {
    F(u32),
    S(u32),
}

pub(crate) const MIXES: [&[W]; 7] = [
    &[W::S(1)],
    &[W::F(56)],
    &[W::S(1), W::F(56), W::F(84), W::S(2)],
    &[W::F(90), W::F(120)],
    &[W::S(1), W::S(3), W::S(0)],
    &[W::S(0), W::S(0)],
    &[W::F(1), W::S(7), W::F(333), W::S(5), W::F(13)],
];

/// The width each column's header hits cover across `at`, or the first
/// point that hits outside `at`, misses inside it, or names a column left
/// of one already passed.
pub(crate) fn spans(t: Table, at: Rect, n: usize) -> Result<Vec<u32>, String> {
    let (x0, x1) = (at.x as i32, (at.x + at.w) as i32);
    let (mut out, mut last) = (vec![0u32; n], 0);
    for x in x0 - 2..x1 + 2 {
        match (t.hit(at, x, at.y as i32), (x0..x1).contains(&x)) {
            (None, false) => {}
            (Some(Cell::Header(c)), true) if c >= last => (out[c], last) = (out[c] + 1, c),
            (h, _) => return Err(format!("x {x} hits {h:?}")),
        }
    }
    Ok(out)
}

/// The columns `mix` describes, each titled `x`.
pub(crate) fn cols(mix: &[W]) -> Vec<Col<'static>> {
    let col = |c: &W| match *c {
        W::F(p) => Col::new("x").fixed(p),
        W::S(n) => Col::new("x").share(n),
    };
    mix.iter().map(col).collect()
}

/// The drawing width of column `c` when fixed, else 0.
pub(crate) fn px(c: &W) -> u32 {
    if let W::F(p) = c {
        scale().px(*p)
    } else {
        0
    }
}

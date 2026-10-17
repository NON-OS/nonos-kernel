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

//! The tick's path walked a pixel at a time, as the dots that draw it.

use super::geometry::Parts;
use crate::widgets::rect::share;

impl Parts {
    /// The centres of the dots that draw the tick, a pixel apart along both
    /// arms.
    pub(super) fn tick_dots(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.tick.windows(2).flat_map(|arm| along(arm[0], arm[1]))
    }
}

/// The pixels from `a` to `b` inclusive, one per step along the longer axis.
fn along(a: (u32, u32), b: (u32, u32)) -> impl Iterator<Item = (u32, u32)> {
    let n = a.0.abs_diff(b.0).max(a.1.abs_diff(b.1)).max(1);
    (0..=n).map(move |i| (towards(a.0, b.0, i, n), towards(a.1, b.1, i, n)))
}

/// `i` steps out of `n` of the way from `a` to `b`.
fn towards(a: u32, b: u32, i: u32, n: u32) -> u32 {
    if b >= a {
        a.saturating_add(share(i, b - a, n))
    } else {
        a.saturating_sub(share(i, a - b, n))
    }
}

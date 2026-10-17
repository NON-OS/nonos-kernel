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

//! How a table's width is shared between its columns.

use alloc::vec::Vec;

use super::col::{Col, Width};
use crate::design::scale::scale;
use crate::widgets::rect::share;

/// The fixed width of `col` in drawing pixels, and its share of the rest.
fn wants(col: &Col) -> (u32, u32) {
    match col.width {
        Width::Fixed(px) => (scale().px(px), 0),
        Width::Share(n) => (0, n),
    }
}

/// The width of each of `cols` across `w`, adding up to exactly `w`. The
/// fixed columns take their widths first and the shared ones split what is
/// left by `rect::share`, each its part of the running total so no pixel is
/// lost to rounding. When `w` is narrower than the fixed columns, they shrink
/// in proportion and the shared ones get nothing. When no column shares, the
/// last takes the room left.
pub(super) fn widths(cols: &[Col], w: u32) -> Vec<u32> {
    let sum =
        |(f, n): (u32, u32), c: &Col| (f.saturating_add(wants(c).0), n.saturating_add(wants(c).1));
    let (fixed, shares) = cols.iter().fold((0, 0), sum);
    let room = w.saturating_sub(fixed);
    let (mut seen, mut out) = ((0u32, 0u32), Vec::with_capacity(cols.len()));
    for c in cols {
        let next = sum(seen, c);
        let f = if w >= fixed {
            wants(c).0
        } else {
            share(next.0, w, fixed).saturating_sub(share(seen.0, w, fixed))
        };
        let n = share(next.1, room, shares).saturating_sub(share(seen.1, room, shares));
        out.push(f.saturating_add(n));
        seen = next;
    }
    let used = out.iter().fold(0u32, |a, b| a.saturating_add(*b));
    if let Some(last) = out.last_mut() {
        *last = last.saturating_add(w.saturating_sub(used));
    }
    out
}

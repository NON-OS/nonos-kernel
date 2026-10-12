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

use alloc::vec::Vec;

use super::rect::Rect;
use super::sidebar_geom::{Row, RowKind};

pub const HEAD_H: i32 = 28;
pub const ROW_H: i32 = 32;
const GAP: i32 = 2;
const STEP: i32 = ROW_H + GAP;

/// The height of a Tab Groups section that lists `shown` groups: its
/// heading, the All tabs row, the group rows and the New group row.
pub fn height(shown: usize) -> i32 {
    HEAD_H + (shown as i32 + 2) * STEP
}

/// How many of `groups` a section given `room` pixels can list, or None
/// when not even its heading and two fixed rows fit.
pub fn fit(room: i32, groups: usize) -> Option<usize> {
    let spare = room - height(0);
    (spare >= 0).then(|| groups.min((spare / STEP) as usize))
}

/// The heading over a section whose top is `top`, across `x..x + w`.
pub fn head(x: i32, w: i32, top: i32) -> Rect {
    Rect::new(x, top, w.max(0), HEAD_H)
}

/// The section's rows under its heading: All tabs, groups `0..shown`, then
/// New group.
pub fn rows(x: i32, w: i32, top: i32, shown: usize) -> Vec<Row> {
    let kinds = core::iter::once(RowKind::AllTabs)
        .chain((0..shown).map(RowKind::Group))
        .chain(core::iter::once(RowKind::NewGroup));
    let y0 = top + HEAD_H;
    let at = |(i, kind): (usize, RowKind)| Row {
        rect: Rect::new(x, y0 + i as i32 * STEP, w.max(0), ROW_H),
        kind,
    };
    kinds.enumerate().map(at).collect()
}

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

//! The placement proof for a widget that opens beside an anchor: the anchors
//! it is opened from, and what is wrong with a rect it was placed at.

use nonos_toolkit::widgets::Rect;

use super::boxes::within;

/// Where a placed widget must open: above or below the anchor, or anywhere.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Side {
    Above,
    Below,
    Free,
}

/// How a placed widget must line up with its anchor across.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Across {
    Centre,
    Left,
}

/// What is wrong with `p`, placed for a widget of `size` by `anchor` inside
/// `bounds`, if anything. It must lie in `bounds`, at its size cut only to
/// `bounds`, on `side`, and lined up with the anchor `across` unless an edge
/// of `bounds` holds it back.
pub(crate) fn fault(
    p: Rect,
    size: (u32, u32),
    anchor: Rect,
    bounds: Rect,
    (side, across): (Side, Across),
) -> Option<&'static str> {
    let centre = i64::from(matches!(across, Across::Centre));
    let mid = |r: Rect| i64::from(r.x) * 2 + i64::from(r.w) * centre;
    let (left, right) = (p.x == bounds.x, p.x + p.w == bounds.x + bounds.w);
    let held = (left && mid(anchor) < mid(p)) || (right && mid(anchor) > mid(p));
    let sided = match side {
        Side::Above => p.y + p.h <= anchor.y,
        Side::Below => p.y >= anchor.y + anchor.h,
        Side::Free => true,
    };
    let checks = [
        (within(p, bounds), "leaves its bounds"),
        ((p.w, p.h) == (size.0.min(bounds.w), size.1.min(bounds.h)), "is cut though it fits"),
        (sided, "opens on the wrong side"),
        ((mid(p) - mid(anchor)).abs() <= 2 * centre || held, "is not lined up with the anchor"),
    ];
    checks.into_iter().find(|(ok, _)| !ok).map(|(_, why)| why)
}

/// An `a` square anchor at each corner, edge middle and the centre of `b`,
/// with its row: 0 along the top, 1 across the middle, 2 along the bottom.
pub(crate) fn anchors(b: Rect, a: u32) -> Vec<(Rect, usize)> {
    let a = a.min(b.w).min(b.h);
    let (sx, sy) = ((b.w - a) / 2, (b.h - a) / 2);
    let at = move |c: u32, r: u32| Rect { x: b.x + c * sx, y: b.y + r * sy, w: a, h: a };
    (0..3).flat_map(|r| (0..3).map(move |c| (at(c, r as u32), r))).collect()
}

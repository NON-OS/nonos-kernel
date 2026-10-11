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

use super::group_rows;
use super::rect::Rect;
use super::sidebar_geom::{rows, RowKind, BRAND_H, DIVIDER, GAP, LOWER, PAD, ROWS, ROW_H, UPPER};

/// The brand row across the top of the full sidebar; empty in the rail.
pub fn brand(rail: bool, side: Rect) -> Rect {
    let h = if rail { 0 } else { BRAND_H };
    Rect::new(side.x, side.y, side.w, h).inset(PAD)
}

/// Where the Tab Groups section starts, under the Tabs row, and how many
/// groups it lists; None in the rail, or when the sidebar is too short to
/// hold it over the library rows and Settings.
pub(super) fn section(rail: bool, side: Rect, groups: usize) -> (i32, Option<usize>) {
    let step = ROW_H + GAP;
    let top = if rail { side.y + PAD } else { side.y + BRAND_H } + UPPER.len() as i32 * step;
    let lib = LOWER.len() as i32 * step - GAP;
    let room = side.bottom() - PAD - ROW_H - 2 * DIVIDER - lib - top;
    (top, if rail { None } else { group_rows::fit(room, groups) })
}

/// The Tab Groups heading, when the section is drawn.
pub fn groups_head(rail: bool, side: Rect, groups: usize) -> Option<Rect> {
    let (top, shown) = section(rail, side, groups);
    shown.map(|_| group_rows::head(side.x + PAD, side.w - 2 * PAD, top))
}

/// The y of the two divider hairlines: over the library rows, and over
/// Settings.
pub fn dividers(rail: bool, side: Rect, groups: usize) -> [i32; 2] {
    let r = rows(rail, side, groups);
    [r[UPPER.len()].rect.y - DIVIDER / 2 - 1, r[ROWS - 1].rect.y - DIVIDER / 2 - 1]
}

/// The row under `(x, y)`, from the same rects the painter draws.
pub fn hit(rail: bool, side: Rect, groups: usize, x: i32, y: i32) -> Option<RowKind> {
    if !side.contains(x, y) {
        return None;
    }
    rows(rail, side, groups).iter().find(|r| r.rect.contains(x, y)).map(|r| r.kind)
}

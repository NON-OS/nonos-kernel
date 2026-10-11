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

use super::rect::Rect;
use super::sidebar_geom::{rows, RowKind, BRAND_H, DIVIDER, PAD};

/// The brand row across the top of the full sidebar; empty in the rail.
pub fn brand(rail: bool, side: Rect) -> Rect {
    let h = if rail { 0 } else { BRAND_H };
    Rect::new(side.x, side.y, side.w, h).inset(PAD)
}

/// The y of the hairline over Settings.
pub fn divider(rail: bool, side: Rect) -> i32 {
    let settings = rows(rail, side).last().map_or(side.y, |r| r.rect.y);
    settings - DIVIDER / 2 - 1
}

/// The row under `(x, y)`, from the same rects the painter draws.
pub fn hit(rail: bool, side: Rect, x: i32, y: i32) -> Option<RowKind> {
    if !side.contains(x, y) {
        return None;
    }
    rows(rail, side).iter().find(|r| r.rect.contains(x, y)).map(|r| r.kind)
}

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

use super::geometry::BUBBLE_BAND;
use super::rect::Rect;

/* The band at the bottom of the page area `page` that holds the
 * hovered-link bubble. */
pub fn bubble_band(page: Rect) -> Rect {
    let bottom = page.y.saturating_add(page.h);
    let y = bottom.saturating_sub(BUBBLE_BAND).max(page.y);
    Rect { x: page.x, y, w: page.w, h: bottom - y }
}

/// What a bubble repaint draws, for its commit to cover: viewport rows
/// `band` (from the page painter's band_rows) of the page area `page`, or
/// the whole page when the band could not be painted alone (None).
pub fn band_commit(band: Option<(i32, i32)>, page: Rect) -> Rect {
    match band {
        Some((a, b)) => {
            let (a, b) = (a.max(0) as u32, b.max(0) as u32);
            Rect { x: page.x, y: page.y.saturating_add(a), w: page.w, h: b.saturating_sub(a) }
        }
        None => page,
    }
}

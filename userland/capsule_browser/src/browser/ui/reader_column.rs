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

use super::reader_geom::{MARGIN, PANEL_W};

pub const MIN_COLUMN: i32 = 420;
const SIDE: i32 = 40;
pub const WIDE_MIN: i32 = PANEL_W + 2 * MARGIN + 2 * SIDE + MIN_COLUMN;
const WIDTHS: [i32; 3] = [560, 680, 820];

/// The article column in a `w` wide content area, as `(x, width)`: the
/// chosen width held inside the room left of the card, centred in it. The
/// card sits beside the column while that leaves it `MIN_COLUMN`, and over
/// it only in an area narrower than `WIDE_MIN`.
pub fn column(w: i32, width: u8) -> (i32, i32) {
    let room = if w >= WIDE_MIN { w - PANEL_W - 2 * MARGIN } else { w };
    let cw = WIDTHS[(width as usize).min(2)].min(room - 2 * SIDE).max(0);
    ((room - cw) / 2, cw)
}

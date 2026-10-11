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

pub use super::areas::{band_commit, bubble_band};
pub use super::rect::Rect;
use crate::browser::ui::rect::Rect as Area;
use crate::browser::ui::toolbar_geom::{buttons, ToolbarGeom};

/* Where the address pill sits inside the toolbar, and the home page inside
 * the page area, in pixels from their top left corner. The painters and the
 * hit tests both read these, so what is drawn and what a click finds can
 * never disagree, at any window width. */

/* The home page search bar and shortcut row. */
pub const SEARCH_W: u32 = 640;
pub const SEARCH_H: u32 = 46;
pub const SEARCH_Y: u32 = 170;
pub const CELL_W: u32 = 150;
pub const BADGE: u32 = 56;
pub const BADGE_Y: u32 = 300;
/* Rows at the bottom of the page that hold the hovered-link bubble. */
pub const BUBBLE_BAND: u32 = 24;

/* Address text size, and the room the truncated-page notice takes at the
 * right end of the text. */
pub const TEXT_PX: f32 = 15.0;
pub const NOTICE_W: u32 = 116;

/* The pill of the toolbar `bar`, from the toolbar geometry its painter and
 * its click handler read. */
pub fn pill_rect(bar: Area) -> Rect {
    Rect::from(toolbar(bar).pill)
}

/* The box the address text is drawn, measured and clicked in, short of
 * the route badge and, on a page cut short, of the notice. */
pub fn pill_text(bar: Area, notice: bool) -> Rect {
    let t = Rect::from(toolbar(bar).text);
    Rect { w: t.w.saturating_sub(if notice { NOTICE_W } else { 0 }), ..t }
}

fn toolbar(bar: Area) -> ToolbarGeom {
    buttons(Area::new(0, 0, bar.w, bar.h))
}

pub fn search_rect(width: u32) -> Rect {
    Rect { x: width.saturating_sub(SEARCH_W) / 2, y: SEARCH_Y, w: SEARCH_W, h: SEARCH_H }
}

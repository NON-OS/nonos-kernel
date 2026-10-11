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

/* Where the chrome sits inside the toolbar, and the home page inside the
 * page area, in pixels from their top left corner. The painters and the hit
 * tests both read these, so what is drawn and what a click finds can never
 * disagree, at any window width. */

pub const BTN_W: i32 = 28;
pub const BACK_X: i32 = 14;
pub const FWD_X: i32 = 46;
pub const RELOAD_X: i32 = 82;
pub const HOME_X: i32 = 114;
pub const PILL_L: u32 = 152;
/* The pill ends this far from the right edge, leaving room for the menu. */
pub const PILL_R_GAP: u32 = 52;
pub const MENU_W: i32 = 44;
/* The home page search bar and shortcut row. */
pub const SEARCH_W: u32 = 640;
pub const SEARCH_H: u32 = 46;
pub const SEARCH_Y: u32 = 170;
pub const CELL_W: u32 = 150;
pub const BADGE: u32 = 56;
pub const BADGE_Y: u32 = 300;
/* Rows at the bottom of the page that hold the hovered-link bubble. */
pub const BUBBLE_BAND: u32 = 24;

pub fn pill_rect(width: u32) -> Rect {
    let r = width.saturating_sub(PILL_R_GAP).max(PILL_L);
    Rect { x: PILL_L, y: 10, w: r - PILL_L, h: 32 }
}

/* Address text: its size, where it starts in the pill, and the room the
 * truncated-page notice takes at the pill's right end. */
pub const TEXT_PX: f32 = 15.0;
pub const PILL_TEXT_X: u32 = 30;
pub const NOTICE_W: u32 = 116;

pub fn pill_text_w(width: u32, notice: bool) -> u32 {
    let room = pill_rect(width).w.saturating_sub(PILL_TEXT_X + 10);
    room.saturating_sub(if notice { NOTICE_W } else { 0 })
}

pub fn search_rect(width: u32) -> Rect {
    Rect { x: width.saturating_sub(SEARCH_W) / 2, y: SEARCH_Y, w: SEARCH_W, h: SEARCH_H }
}

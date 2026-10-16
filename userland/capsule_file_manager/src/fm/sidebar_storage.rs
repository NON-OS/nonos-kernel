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

extern crate alloc;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Progress, Rect};

use super::chrome_card::Plate;
use super::icon_draw::draw;
use super::icon_path::Icon;
use super::layout::R_CARD;
use super::measure_text::truncate_to_width;
use super::sidebar_metrics::{line_box, rail_text_x, rail_w, ICON_S, RAIL_PAD, RAIL_X};
use super::sidebar_usage::{fill_pct, occupancy};
use super::state::State;

// Card band: the plate itself, then the gap holding it clear of the window foot.
pub const CARD_H: u32 = 88;
pub const CARD_FOOT: u32 = 16;

const TITLE_PX: f32 = 18.0;
const SUB_PX: f32 = 13.0;
const BAR_H: u32 = 6;
const CHEVRON: u32 = 14;
const DRIVE: &str = "NØNOS Drive";

/// The drive card pinned to the foot of the rail. Every figure on it comes from
/// the cached `vfs::usage` read taken on refresh, never from a call made inside
/// paint.
pub fn paint_storage(state: &State, fb: &mut PaintBuffer, y: u32) {
    let (w, r) = (rail_w(), roles());
    Plate::new(r.surface.argb()).radius(R_CARD).tint().draw(fb, RAIL_X, y, w, CARD_H);
    let head = y + RAIL_PAD;
    draw(fb, Icon::Cube, RAIL_X + RAIL_PAD, head, ICON_S, r.accent.argb());
    let ty = head + ICON_S.saturating_sub(line_box(TITLE_PX)) / 2;
    let _ = fb.text_ttf(rail_text_x() as i32, ty as i32, DRIVE, r.text.argb(), TITLE_PX);
    let cx = RAIL_X + w.saturating_sub(RAIL_PAD + CHEVRON);
    draw(fb, Icon::Chevron, cx, head + ICON_S.saturating_sub(CHEVRON) / 2, CHEVRON, r.muted.argb());
    let inner = w.saturating_sub(RAIL_PAD * 2);
    let bar_y = head + ICON_S + RAIL_PAD;
    let track = Rect { x: RAIL_X + RAIL_PAD, y: bar_y, w: inner, h: BAR_H };
    Progress::new(fill_pct(state).min(100), 100).draw(fb, track);
    let line = occupancy(state);
    let cut = truncate_to_width(fb, line.as_str(), SUB_PX, inner);
    let ty = (bar_y + BAR_H + 6) as i32;
    let _ = fb.text_ttf((RAIL_X + RAIL_PAD) as i32, ty, cut, r.muted.argb(), SUB_PX);
}

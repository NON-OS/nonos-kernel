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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Progress, Rect};

use super::chrome_card::Plate;
use super::home_cat_geom::CatCell;
use super::home_stor_geom::{stor_cells, STOR_PLACES};
use super::home_stor_text::{bar_pct, detail, size_text};
use super::icon_draw::draw;
use super::icon_path::Icon;
use super::layout::R_CARD;
use super::measure_text::{right_text, truncate_to_width, width_of};
use super::state::State;

const PAD: u32 = 12;
const ICON: u32 = 18;
const BAR_H: u32 = 6;
const TITLE_PX: f32 = 15.0;
const SUB_PX: f32 = 13.0;

/// Draws the storage row from the same cells `home_hit` tests against. Every
/// figure on it comes from the cached `usage` and `dirstat` reads taken before
/// paint, never from a call made inside it.
pub fn paint_storage_row(state: &State, fb: &mut PaintBuffer) {
    for cell in stor_cells(state.win_w, state.win_h) {
        card(state, fb, &cell);
    }
}

fn card(state: &State, fb: &mut PaintBuffer, c: &CatCell) {
    let (title, path) = STOR_PLACES[c.idx];
    let r = roles();
    let muted = r.muted.argb();
    Plate::new(r.surface.argb()).radius(R_CARD).tint().draw(fb, c.x, c.y, c.w, c.h);
    let inner = c.w.saturating_sub(PAD * 2);
    let tx = c.x + PAD;
    draw(fb, Icon::Cube, tx, c.y + PAD, ICON, r.accent.argb());
    let size = size_text(state, c.idx, path);
    let room = inner.saturating_sub(ICON + width_of(fb, size.as_str(), SUB_PX) + PAD * 2);
    let cut = truncate_to_width(fb, title, TITLE_PX, room);
    let _ = fb.text_ttf((tx + ICON + 10) as i32, (c.y + PAD) as i32, cut, r.text.argb(), TITLE_PX);
    right_text(fb, (c.x + c.w).saturating_sub(PAD), c.y + PAD, size.as_str(), SUB_PX, muted);
    let track = Rect { x: tx, y: c.y + PAD + 24, w: inner, h: BAR_H };
    Progress::new(bar_pct(state, c.idx, path).min(100), 100).draw(fb, track);
    let line = detail(state, c.idx, path);
    let shown = truncate_to_width(fb, line.as_str(), SUB_PX, inner);
    let _ = fb.text_ttf(tx as i32, (c.y + PAD + 34) as i32, shown, muted, SUB_PX);
}

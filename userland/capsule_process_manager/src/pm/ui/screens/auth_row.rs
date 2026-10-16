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
use nonos_toolkit::icons::{draw, IconId};
use nonos_toolkit::theme::roles;

use crate::pm::state::{Row, State};

use super::super::chrome::Rect;
use super::super::matrix_geom as geom;
use super::super::metrics::{BODY_PX, ROW_ICON, ROW_ICON_GAP, SEL_BAR_W};
use super::super::text;
use super::auth_cells;

// The accent wash carries alpha, so it blends; the zebra band, the opaque
// surface a step up from the inset matrix, may be written. The inset of one pixel keeps both inside the stroked border the screen draws last.
pub fn paint(state: &State, fb: &mut PaintBuffer, r: &Rect, row: &Row, slot: usize) {
    let (c, y) = (roles(), r.y + geom::row_y(slot));
    let body_w = r.w.saturating_sub(2);
    if row.pid == state.selected_pid && state.selected_pid != 0 {
        fb.blend_rect(r.x + 1, y, body_w, geom::ROW_H, c.accent_wash.argb());
        fb.fill_rect(r.x + 1, y, SEL_BAR_W, geom::ROW_H, c.accent.argb());
    } else if (state.scroll + slot) % 2 == 1 {
        fb.fill_rect(r.x + 1, y, body_w, geom::ROW_H, c.surface.argb());
    }
    let protected = state.is_protected(row);
    name(fb, r, row, y, protected);
    auth_cells::paint(fb, r, row, y, protected);
}

// A kernel-protected process wears the shield, which is what makes the danger
// rings on every other row mean something.
fn name(fb: &mut PaintBuffer, r: &Rect, row: &Row, y: u32, protected: bool) {
    let (c, mut x) = (roles(), r.x + geom::PAD_X);
    let mut avail = geom::NAME_W.saturating_sub(geom::PAD_X * 2);
    if protected {
        let iy = y + (geom::ROW_H - ROW_ICON) / 2;
        draw(fb, IconId::SettingsSecurity, x, iy, ROW_ICON, c.accent.argb());
        x += ROW_ICON + ROW_ICON_GAP;
        avail = avail.saturating_sub(ROW_ICON + ROW_ICON_GAP);
    }
    let cut = text::fit(fb, row.name(), BODY_PX, avail);
    let top = text::centred_top(y, geom::ROW_H, BODY_PX);
    text::left(fb, x, top, cut, c.text_2, BODY_PX);
}

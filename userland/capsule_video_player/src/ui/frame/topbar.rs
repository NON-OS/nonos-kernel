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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::region::{search, tool};
use crate::ui::icon;
use crate::ui::layout::Rect;
use crate::ui::paint::{rrect, shape};
use crate::ui::widget::field::paint_field;

pub const VIEW_W: u32 = 78;
const HALF: u32 = VIEW_W / 2;
const GLYPH: u32 = 16;

pub fn view_toggle(w: u32, h: u32) -> Rect {
    tool(w, h, 0, VIEW_W)
}

pub fn grid_half(r: Rect) -> Rect {
    Rect { x: r.x, y: r.y, w: HALF, h: r.h }
}

pub fn list_half(r: Rect) -> Rect {
    Rect { x: r.x + HALF, y: r.y, w: r.w.saturating_sub(HALF), h: r.h }
}

fn paint_view(fb: &mut PaintBuffer, r: Rect, grid: bool) {
    let theme = roles();
    rrect::panel(fb, r.x, r.y, r.w, r.h, 8, theme.surface.argb(), theme.border.argb());
    let live = if grid { grid_half(r) } else { list_half(r) };
    rrect::fill_round(fb, live.x + 2, r.y + 2, live.w - 4, r.h - 4, 6, theme.raised.argb());
    shape::vline(fb, r.x + HALF, r.y + 6, r.h.saturating_sub(12), theme.border.argb());
    let gy = r.y + r.h.saturating_sub(GLYPH) / 2;
    let on = theme.accent.argb();
    let off = theme.muted.argb();
    let g = grid_half(r);
    let l = list_half(r);
    let gx = g.x + g.w.saturating_sub(GLYPH) / 2;
    let lx = l.x + l.w.saturating_sub(GLYPH) / 2;
    icon::ui::grid(fb, gx, gy, GLYPH, if grid { on } else { off });
    icon::ui::list(fb, lx, gy, GLYPH, if grid { off } else { on });
}

pub fn paint_search(fb: &mut PaintBuffer, w: u32, h: u32, hint: &str, query: &str) {
    paint_field(fb, search(w, h), hint, query, !query.is_empty());
}

/// The grid and list switch. The list is always sorted by name and holds only
/// playable videos, so there is no sort or filter menu beside it.
pub fn paint_tools(fb: &mut PaintBuffer, w: u32, h: u32, grid: bool) {
    paint_view(fb, view_toggle(w, h), grid);
}

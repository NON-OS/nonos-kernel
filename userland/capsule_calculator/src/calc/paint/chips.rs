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
use nonos_toolkit::font::ttf::line_height;
use nonos_toolkit::theme::roles;

use crate::calc::convert::CATEGORIES;
use crate::calc::hit::Hit;
use crate::calc::state::State;
use crate::calc::ui::convert_geom::chip;
use crate::calc::ui::convert_hit::ConvertHit;
use crate::calc::ui::metrics::{PX_TITLE, R_KEY};
use crate::calc::ui::trim::trim;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let win_w = fb.width as i32;
    let (r, lh) = (roles(), line_height(PX_TITLE).max(1));
    for (i, cat) in CATEGORIES.iter().enumerate() {
        let (x, y, w, h) = chip(win_w, i);
        if w <= 0 || x < 0 || y < 0 {
            return;
        }
        let active = state.cat == *cat;
        let (ux, uy, uw, uh) = (x as u32, y as u32, w as u32, h as u32);
        let radius = R_KEY as u32;
        let (body, edge) = if active {
            (r.accent_wash.argb(), r.accent_edge.argb())
        } else {
            (r.raised.argb(), r.border.argb())
        };
        fb.fill_round(ux, uy, uw, uh, radius, body);
        fb.stroke_round(ux, uy, uw, uh, radius, 1, edge);
        if !active && state.hover == Some(Hit::Convert(ConvertHit::Chip(i))) {
            fb.blend_rect(ux, uy, uw, uh, r.hover_wash.argb());
        }
        let (label, _) = trim(fb, cat.label(), w - 12, PX_TITLE);
        let tx = x + (w - fb.measure_ttf(label, PX_TITLE)) / 2;
        let ink = if active { r.accent } else { r.muted };
        fb.text_ttf(tx, y + (h - lh) / 2, label, ink.argb(), PX_TITLE);
    }
}

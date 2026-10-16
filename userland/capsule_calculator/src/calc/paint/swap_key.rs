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

use super::button::lit;
use crate::calc::hit::Hit;
use crate::calc::state::State;
use crate::calc::ui::convert_geom::swap;
use crate::calc::ui::convert_hit::ConvertHit;
use crate::calc::ui::metrics::{PX_KEY, R_KEY};

const LABEL: &str = "<->";

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let (x, y, w, h) = swap(fb.width as i32);
    if w <= 0 || h <= 0 || x < 0 || y < 0 {
        return;
    }
    let (ux, uy, uw, uh) = (x as u32, y as u32, w as u32, h as u32);
    let (radius, r) = (R_KEY as u32, roles());
    fb.fill_round(ux, uy, uw, uh, radius, lit());
    fb.stroke_round(ux, uy, uw, uh, radius, 1, r.border.argb());
    if state.hover == Some(Hit::Convert(ConvertHit::Swap)) {
        fb.blend_rect(ux, uy, uw, uh, r.hover_wash.argb());
        fb.stroke_round(ux, uy, uw, uh, radius, 1, r.accent_edge.argb());
    }
    let tx = x + (w - fb.measure_ttf(LABEL, PX_KEY)) / 2;
    let ty = y + (h - line_height(PX_KEY).max(1)) / 2;
    fb.text_ttf(tx, ty, LABEL, r.accent.argb(), PX_KEY);
}

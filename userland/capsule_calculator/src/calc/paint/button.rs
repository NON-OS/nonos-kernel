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
use nonos_toolkit::theme::derive::mix;
use nonos_toolkit::theme::roles;

use crate::calc::buttons::{Button, Role};
use crate::calc::ui::metrics::{PX_KEY, R_KEY};

pub fn paint(
    fb: &mut PaintBuffer,
    btn: &Button,
    rect: (i32, i32, i32, i32),
    hover: bool,
    enabled: bool,
) {
    let (x, y, w, h) = rect;
    if w <= 0 || h <= 0 || x < 0 || y < 0 {
        return;
    }
    let r = roles();
    let (key, text, muted) = (r.raised.argb(), r.text.argb(), r.muted.argb());
    let (bg, fg) = match btn.role {
        Role::Number => (key, text),
        Role::Operator => (lit(), text),
        Role::Equals => (r.accent.argb(), r.on_accent.argb()),
        Role::Function => (key, muted),
        Role::Memory => (key, muted),
    };
    let (bg, fg) = if enabled { (bg, fg) } else { (key, r.disabled.argb()) };
    let (ux, uy, uw, uh) = (x as u32, y as u32, w as u32, h as u32);
    let radius = R_KEY as u32;
    fb.fill_round(ux, uy, uw, uh, radius, bg);
    fb.stroke_round(ux, uy, uw, uh, radius, 1, r.border.argb());
    if hover && enabled {
        fb.blend_rect(ux, uy, uw, uh, r.hover_wash.argb());
        fb.stroke_round(ux, uy, uw, uh, radius, 1, r.accent_edge.argb());
    }
    let tx = x + (w - fb.measure_ttf(btn.label, PX_KEY)) / 2;
    let ty = y + (h - line_height(PX_KEY).max(1)) / 2;
    fb.text_ttf(tx, ty, btn.label, fg, PX_KEY);
}

/// The body of a key that stands out from the number keys: an operator, the
/// swap key, a set bit. The key body a step towards the accent.
pub fn lit() -> u32 {
    let r = roles();
    mix(r.raised.argb(), r.accent.argb(), 32)
}

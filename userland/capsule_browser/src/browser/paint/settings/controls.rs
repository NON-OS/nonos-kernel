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

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use super::caption::caption;
use super::field;
use super::look::{look, Look};
use super::page::PX;
use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens::palette;
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::ui::fit::truncate_to;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::settings_geom::Control;

const RADIUS: u32 = 10;
const ICON: i32 = 16;

/// The control `c` in `r`.
pub fn paint(fb: &mut PaintBuffer, state: &State, shell: &Shell, c: Control, r: Rect) {
    if let Control::Field(f) = c {
        return field::paint(fb, shell, f, r);
    }
    let p = palette();
    let (fill, edge, ink) = match look(state, shell, c) {
        Look::On => (p.accent, p.accent, p.on_accent),
        Look::Off => (p.field, p.field, p.ink2),
        Look::Plain => (p.surface, p.edge, p.ink),
        Look::Danger => (p.surface, p.edge, p.err),
        Look::Armed => (p.warn_soft, p.err, p.err),
        Look::Dim => (p.field, p.field, p.disabled),
    };
    let (x, y, w, h) = (r.x as u32, r.y as u32, r.w as u32, r.h as u32);
    fb.fill_round(x, y, w, h, RADIUS, fill);
    fb.stroke_round(x, y, w, h, RADIUS, 1, edge);
    let (cx, cy) = (r.x + r.w / 2, r.y + r.h / 2);
    match c {
        Control::Smaller => {
            fb.fill_rect((cx - ICON / 3) as u32, (cy - 1) as u32, (2 * ICON / 3) as u32, 2, ink)
        }
        Control::Larger => glyph::draw(fb, Glyph::Plus, cx, cy, ICON, ink),
        _ => {
            let s = truncate_to(&caption(shell, c), r.w - 12, |t| measure_ttf(t, PX));
            let tx = r.x + (r.w - measure_ttf(&s, PX)) / 2;
            fb.text_ttf(tx, r.y + (r.h - line_height(PX)) / 2, &s, ink, PX);
        }
    }
}

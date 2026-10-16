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
use nonos_toolkit::theme::{roles, Roles};

use super::layout::{indent, line_height, px, Line, Style};

pub const MARGIN: i32 = 24;

/// The ink a markdown style is drawn in: the top two headings in the accent,
/// the third in muted, code in text_2 on its raised band, the rest in text.
fn colour(r: &Roles, style: Style) -> u32 {
    match style {
        Style::H1 | Style::H2 => r.accent.argb(),
        Style::H3 => r.muted.argb(),
        Style::Code => r.text_2.argb(),
        _ => r.text.argb(),
    }
}

pub fn draw_line(fb: &mut PaintBuffer, line: &Line, y: i32) {
    let (r, height) = (roles(), line_height(line.style));
    if line.style == Style::Code {
        let band = fb.width.saturating_sub(2 * MARGIN as u32 - 16);
        let left = (MARGIN - 8).max(0) as u32;
        fb.fill_rect(left, y as u32, band, height as u32, r.raised.argb());
    }
    let mut x = MARGIN + indent(line.style);
    if line.style == Style::Bullet && line.lead {
        fb.fill_rect((x - 14) as u32, (y + height / 2 - 2) as u32, 4, 4, r.accent.argb());
    }
    let size = px(line.style);
    let colour = colour(&r, line.style);
    for span in &line.spans {
        x = if span.mono {
            fb.text_ttf_mono(x, y, &span.text, colour, size)
        } else {
            fb.text_ttf(x, y, &span.text, colour, size)
        };
    }
}

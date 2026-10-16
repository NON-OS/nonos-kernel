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

use super::draw::{draw_line, MARGIN};
use super::layout::{line_height, Line};
use super::scroll::{place, TOP};

/// Draws the lines wholly inside the window once the page is scrolled up by
/// `scroll` pixels.
pub fn paint(fb: &mut PaintBuffer, lines: &[Line], error: Option<&'static str>, scroll: u32) {
    let (r, bottom) = (roles(), fb.height as i32);
    fb.clear(r.bg.argb());
    fb.fill_rect(0, 0, fb.width, 4, r.accent.argb());
    if let Some(message) = error {
        fb.text_ttf(MARGIN, TOP, message, r.danger.argb(), 15.0);
        fb.text_ttf(MARGIN, TOP + 26, "esc closes this window", r.quiet.argb(), 13.0);
        return;
    }
    place(lines, |top, line| {
        let y = top - scroll as i32;
        if y >= 0 && y + line_height(line.style) <= bottom {
            draw_line(fb, line, y);
        }
    });
    /* A line scrolled up to the top edge is drawn under the accent band. */
    fb.fill_rect(0, 0, fb.width, 4, r.accent.argb());
}

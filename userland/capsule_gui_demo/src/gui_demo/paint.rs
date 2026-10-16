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
use nonos_toolkit::widgets::{Card, Rect};

use super::decimal::{render_u32, DIGITS};
use super::manifest::WIDTH;

pub fn paint(fb: &mut PaintBuffer, clicks: u32) {
    let r = roles();
    fb.clear(r.bg.argb());
    fb.fill_rect(0, 0, WIDTH, 4, r.accent.argb());
    fb.text_scaled(24, 36, b"gui demo", r.accent.argb(), 2);
    fb.text(24, 76, b"click the window to count", r.text.argb());
    Card::new().draw(fb, Rect { x: 24, y: 100, w: 332, h: 60 });
    fb.text(40, 122, b"clicks", r.muted.argb());
    let mut buf = [0u8; DIGITS];
    fb.text_scaled(140, 112, render_u32(clicks, &mut buf), r.text_2.argb(), 3);
    fb.text(24, 186, b"press Esc to close", r.quiet.argb());
}

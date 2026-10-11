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

use super::kind::Glyph;
use super::pen::Pen;
use super::{actions, nav, objects};

/// Stroke `g` centred on `(cx, cy)`, `size` pixels across, in `argb`.
pub fn draw(fb: &mut PaintBuffer, g: Glyph, cx: i32, cy: i32, size: i32, argb: u32) {
    let pen = Pen::new(cx, cy, size, argb);
    match g {
        Glyph::Back => nav::back(fb, &pen),
        Glyph::Forward => nav::forward(fb, &pen),
        Glyph::Reload => nav::reload(fb, &pen),
        Glyph::Home => nav::home(fb, &pen),
        Glyph::Search => nav::search(fb, &pen),
        Glyph::Lock => nav::lock(fb, &pen),
        Glyph::Close => actions::close(fb, &pen),
        Glyph::Sidebar => actions::sidebar(fb, &pen),
        Glyph::Sliders => actions::sliders(fb, &pen),
        Glyph::Star => objects::star(fb, &pen, false),
        Glyph::StarFilled => objects::star(fb, &pen, true),
        Glyph::Shield => objects::shield(fb, &pen),
    }
}

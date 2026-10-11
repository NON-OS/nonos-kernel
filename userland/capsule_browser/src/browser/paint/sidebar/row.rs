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

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens;
use crate::browser::ui::sidebar_geom::{Row, RowKind};

const ICON: i32 = 20;
const ICON_X: i32 = 22;
const TEXT_X: i32 = 44;
const TEXT_PX: f32 = 17.0;
const RADIUS: u32 = 10;

fn look(kind: RowKind) -> (Glyph, &'static str) {
    match kind {
        RowKind::Start => (Glyph::Home, "Start Page"),
        RowKind::Settings => (Glyph::Sliders, "Settings"),
    }
}

/// One sidebar row: an accent pill with white ink when active, the glyph,
/// and in the full sidebar the label.
pub fn paint(fb: &mut PaintBuffer, row: &Row, rail: bool, active: bool) {
    let r = row.rect;
    let (g, label) = look(row.kind);
    let ink = if active { tokens::ON_ACCENT } else { tokens::INK2 };
    if active {
        fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, tokens::ACCENT);
    }
    let cy = r.y + r.h / 2;
    if rail {
        glyph::draw(fb, g, r.x + r.w / 2, cy, ICON, ink);
        return;
    }
    glyph::draw(fb, g, r.x + ICON_X, cy, ICON, ink);
    let ty = r.y + (r.h - line_height(TEXT_PX)) / 2;
    fb.text_ttf(r.x + TEXT_X, ty, label, ink, TEXT_PX);
}

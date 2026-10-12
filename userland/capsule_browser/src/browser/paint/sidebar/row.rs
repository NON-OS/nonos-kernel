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

use alloc::format;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens::palette;
use crate::browser::ui::sidebar_geom::{Row, RowKind};

const ICON: i32 = 20;
const ICON_X: i32 = 22;
const TEXT_X: i32 = 44;
const TEXT_PX: f32 = 17.0;
const RADIUS: u32 = 10;
const COUNT_PAD: i32 = 12;

fn look(kind: RowKind) -> (Glyph, &'static str) {
    match kind {
        RowKind::Start => (Glyph::Home, "Start Page"),
        RowKind::Tabs => (Glyph::Tabs, "Tabs"),
        RowKind::Bookmarks => (Glyph::Star, "Bookmarks"),
        RowKind::Reader => (Glyph::Reader, "Reading View"),
        RowKind::Downloads => (Glyph::Download, "Downloads"),
        RowKind::History => (Glyph::Clock, "History"),
        RowKind::Settings => (Glyph::Sliders, "Settings"),
        RowKind::AllTabs => (Glyph::Layers, "All tabs"),
        RowKind::NewGroup => (Glyph::Plus, "New group"),
        RowKind::Group(_) => (Glyph::Layers, ""),
    }
}

/// One sidebar row: an accent pill with white ink when active, the glyph,
/// and in the full sidebar the label and, for Tabs, the open-tab count.
pub fn paint(fb: &mut PaintBuffer, row: &Row, rail: bool, active: bool, tabs: usize) {
    let r = row.rect;
    let (g, label) = look(row.kind);
    let (ink, soft) = match active {
        true => (palette().on_accent, palette().on_accent),
        false => (palette().ink2, palette().muted),
    };
    if active {
        fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, palette().accent);
    }
    let cy = r.y + r.h / 2;
    if rail {
        glyph::draw(fb, g, r.x + r.w / 2, cy, ICON, ink);
        return;
    }
    glyph::draw(fb, g, r.x + ICON_X, cy, ICON, ink);
    let ty = r.y + (r.h - line_height(TEXT_PX)) / 2;
    fb.text_ttf(r.x + TEXT_X, ty, label, ink, TEXT_PX);
    if row.kind == RowKind::Tabs {
        let n = format!("{}", tabs);
        let nx = r.right() - COUNT_PAD - measure_ttf(&n, TEXT_PX);
        fb.text_ttf(nx, ty, &n, soft, TEXT_PX);
    }
}

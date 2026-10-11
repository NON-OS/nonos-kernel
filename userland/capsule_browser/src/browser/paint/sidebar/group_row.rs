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
use crate::browser::paint::tokens;
use crate::browser::shell::groups::{self, MAX_GROUPS};
use crate::browser::shell::kept::Group;
use crate::browser::ui::fit;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::sidebar_geom::Row;

const DOT: i32 = 12;
const DOT_X: i32 = 22;
const TEXT_X: i32 = 44;
const PX: f32 = 17.0;
const RADIUS: u32 = 10;
const COUNT_PAD: i32 = 12;
const NAME_GAP: i32 = 8;
const ICON: i32 = 18;

/// One group row: an accent pill with white ink when it is the filter in
/// force, the group's colour dot, its name and how many open tabs it holds.
pub fn paint(fb: &mut PaintBuffer, row: &Row, g: &Group, active: bool, members: &[Option<u8>]) {
    let r = row.rect;
    let (ink, soft) = match active {
        true => (tokens::ON_ACCENT, tokens::ON_ACCENT),
        false => (tokens::INK2, tokens::MUTED),
    };
    if active {
        fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, tokens::ACCENT);
    }
    let dot = Rect::new(r.x + DOT_X - DOT / 2, r.y + (r.h - DOT) / 2, DOT, DOT);
    let tint = tokens::TILES[g.color as usize % tokens::TILES.len()];
    fb.fill_round(dot.x as u32, dot.y as u32, DOT as u32, DOT as u32, (DOT / 2) as u32, tint);
    let n = format!("{}", groups::count(g.id, members));
    let nx = r.right() - COUNT_PAD - measure_ttf(&n, PX);
    let ty = r.y + (r.h - line_height(PX)) / 2;
    fb.text_ttf(nx, ty, &n, soft, PX);
    let name = fit::truncate_to(&g.name, nx - NAME_GAP - r.x - TEXT_X, |t| measure_ttf(t, PX));
    fb.text_ttf(r.x + TEXT_X, ty, &name, ink, PX);
}

/// The muted "Tab Groups" heading over the section.
pub fn heading(fb: &mut PaintBuffer, r: Rect) {
    let ty = r.y + (r.h - line_height(PX)) / 2;
    fb.text_ttf(r.x + NAME_GAP, ty, "Tab Groups", tokens::MUTED, PX);
}

/// The New group row, dimmed once the window holds `MAX_GROUPS`.
pub fn new_group(fb: &mut PaintBuffer, r: Rect, held: usize) {
    let ink = if held >= MAX_GROUPS { tokens::DISABLED } else { tokens::INK2 };
    glyph::draw(fb, Glyph::Plus, r.x + DOT_X, r.y + r.h / 2, ICON, ink);
    let ty = r.y + (r.h - line_height(PX)) / 2;
    fb.text_ttf(r.x + TEXT_X, ty, "New group", ink, PX);
}

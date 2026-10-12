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

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::pages::rows::{PAD, PX, TILE};
use crate::browser::paint::start::{letter_tile, tile_color, tile_letter};
use crate::browser::paint::tokens::palette;
use crate::browser::ui::list_geom::trail;
use crate::browser::ui::rect::Rect;

const TILE_RADIUS: u32 = 10;
const GLYPH: i32 = 18;

/// A tile `w` wide at the left of `row`, with `text` on it.
pub fn tile(fb: &mut PaintBuffer, row: Rect, text: &str, color: u32, w: i32) {
    let t = Rect::new(row.x + PAD, row.y + (row.h - TILE) / 2, w, TILE);
    letter_tile(fb, t, TILE_RADIUS, text, color, PX);
}

/// The lettered tile the start page gives `host`.
pub fn site_tile(fb: &mut PaintBuffer, row: Rect, host: &str) {
    let mut buf = [0u8; 4];
    let letter = tile_letter(host).encode_utf8(&mut buf);
    tile(fb, row, letter, tile_color(host), TILE);
}

/// `s` on the row's centre line, ending at `right`; returns where it starts.
pub fn right_text(fb: &mut PaintBuffer, row: Rect, right: i32, s: &str, ink: u32) -> i32 {
    let x = right - measure_ttf(s, PX);
    fb.text_ttf(x, row.y + (row.h - line_height(PX)) / 2, s, ink, PX);
    x
}

/// `g` on the row's centre line, ending at `right`; returns where it starts.
pub fn right_glyph(fb: &mut PaintBuffer, row: Rect, right: i32, g: Glyph, ink: u32) -> i32 {
    glyph::draw(fb, g, right - GLYPH / 2, row.y + row.h / 2, GLYPH, ink);
    right - GLYPH
}

/// The row's action glyph in its trailing square; returns where that starts.
pub fn trail_glyph(fb: &mut PaintBuffer, row: Rect, g: Glyph) -> i32 {
    let t = trail(row);
    glyph::draw(fb, g, t.x + t.w / 2, t.y + t.h / 2, GLYPH, palette().muted);
    t.x
}

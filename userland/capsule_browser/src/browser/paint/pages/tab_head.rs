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

use alloc::string::String;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::start::{letter_tile, tile_letter};
use crate::browser::paint::tokens;
use crate::browser::ui::fit;
use crate::browser::ui::grid_geom::close_rect;
use crate::browser::ui::rect::Rect;

pub const PAD: i32 = 14;
pub const HEAD_H: i32 = 64;
const TILE: i32 = 32;
const TILE_RADIUS: u32 = 9;
const TEXT_GAP: i32 = 10;
const PX: f32 = 17.0;
const GLYPH: i32 = 16;

/// The card's top strip: the site tile, title over host, and the close button.
pub fn head(fb: &mut PaintBuffer, r: Rect, title: &str, host: &str, color: u32) {
    let mut buf = [0u8; 4];
    let letter = tile_letter(host).encode_utf8(&mut buf);
    let t = Rect::new(r.x + PAD, r.y + (HEAD_H - TILE) / 2, TILE, TILE);
    letter_tile(fb, t, TILE_RADIUS, letter, color, PX);
    let close = close_rect(r);
    let (cx, cy) = (close.x + close.w / 2, close.y + close.h / 2);
    if close.y >= 0 {
        glyph::draw(fb, Glyph::Close, cx, cy, GLYPH, tokens::MUTED);
    }
    let (x, lh) = (t.right() + TEXT_GAP, line_height(PX));
    let top = r.y + (HEAD_H - 2 * lh) / 2;
    fb.text_ttf(x, top, &cut(title, PX, close.x - x), tokens::INK, PX);
    fb.text_ttf(x, top + lh, &cut(host, PX, close.x - x), tokens::MUTED, PX);
}

pub fn cut(s: &str, px: f32, w: i32) -> String {
    fit::truncate_to(s, w, |t| measure_ttf(t, px))
}

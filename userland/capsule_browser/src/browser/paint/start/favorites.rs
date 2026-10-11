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

use crate::browser::paint::clip;
use crate::browser::paint::start::fav_list::Fav;
use crate::browser::paint::tokens;
use crate::browser::ui::fit;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::start_geom::{fav_rect, StartGeom};

const TITLE_PX: f32 = 18.0;
const TILE: i32 = 60;
const TILE_RADIUS: u32 = 16;
const LETTER_PX: f32 = 26.0;
const LABEL_PX: f32 = 17.0;
const LABEL_GAP: i32 = 8;
const LABEL_PAD: i32 = 4;

/// The "Favourites" heading and one lettered tile per favourite.
pub fn paint(g: &StartGeom, favs: &[Fav], fb: &mut PaintBuffer) {
    if g.favs == 0 {
        return;
    }
    let first = fav_rect(g, 0);
    fb.text_ttf(first.x, g.fav_title_y, "Favourites", tokens::INK2, TITLE_PX);
    for (i, f) in favs.iter().enumerate().take(g.favs) {
        tile(fb, fav_rect(g, i), f);
    }
}

fn tile(fb: &mut PaintBuffer, cell: Rect, f: &Fav) {
    let t = Rect::new(cell.x + (cell.w - TILE) / 2, cell.y, TILE, TILE);
    let mut buf = [0u8; 4];
    letter_tile(fb, t, TILE_RADIUS, f.letter.encode_utf8(&mut buf), f.color, LETTER_PX);
    let shown = fit::truncate_to(&f.label, cell.w - 2 * LABEL_PAD, |s| measure_ttf(s, LABEL_PX));
    let tx = cell.x + (cell.w - measure_ttf(&shown, LABEL_PX)) / 2;
    fb.text_ttf(tx, t.bottom() + LABEL_GAP, &shown, tokens::INK2, LABEL_PX);
}

/// A coloured tile with `text` centred on it in white.
pub fn letter_tile(fb: &mut PaintBuffer, t: Rect, radius: u32, text: &str, color: u32, px: f32) {
    clip::round(fb, t, radius, color);
    let lx = t.x + (t.w - measure_ttf(text, px)) / 2;
    let ly = t.y + (t.h - line_height(px)) / 2;
    fb.text_ttf(lx, ly, text, tokens::ON_ACCENT, px);
}

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

use super::panel::LABEL_PX;
use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens::{self, palette};
use crate::browser::shell::kept::{ReaderPrefs, MAX_SIZE};
use crate::browser::ui::fit::truncate_to;
use crate::browser::ui::reader_geom::ReaderGeom;
use crate::browser::ui::rect::Rect;

const RADIUS: u32 = 10;
const THEMES: [&str; 3] = ["Light", "Sepia", "Dark"];
const WIDTHS: [&str; 3] = ["Narrow", "Standard", "Wide"];
const DOT: i32 = 8;
const STEPS: i32 = 5;
const ICON: i32 = 16;

pub fn swatches(p: &ReaderPrefs, g: &ReaderGeom, fb: &mut PaintBuffer) {
    for (i, r) in g.swatches.iter().enumerate() {
        let [bg, fg, _] = tokens::READER_THEMES[i];
        let (t, edge) =
            if p.theme as usize == i { (2, palette().accent) } else { (1, palette().edge) };
        fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, bg);
        fb.stroke_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, t, edge);
        centred(fb, *r, THEMES[i], fg);
    }
}

pub fn size(p: &ReaderPrefs, g: &ReaderGeom, fb: &mut PaintBuffer) {
    let minus = button(fb, g.minus, p.size > 0);
    let (cx, cy) = (g.minus.x + g.minus.w / 2, g.minus.y + g.minus.h / 2);
    fb.fill_rect((cx - ICON / 3) as u32, (cy - 1) as u32, (2 * ICON / 3) as u32, 2, minus);
    let plus = button(fb, g.plus, p.size < MAX_SIZE);
    glyph::draw(fb, Glyph::Plus, g.plus.x + g.plus.w / 2, cy, ICON, plus);
    let step = g.dots.w / (STEPS + 1);
    for i in 0..STEPS {
        let on = i <= p.size as i32;
        let x = g.dots.x + step * (i + 1) - DOT / 2;
        let argb = if on { palette().accent } else { palette().edge };
        fb.fill_round(
            x as u32,
            (cy - DOT / 2) as u32,
            DOT as u32,
            DOT as u32,
            DOT as u32 / 2,
            argb,
        );
    }
}

pub fn widths(p: &ReaderPrefs, g: &ReaderGeom, fb: &mut PaintBuffer) {
    for (i, r) in g.widths.iter().enumerate() {
        let (fill, ink) = match p.width as usize == i {
            true => (palette().accent, palette().on_accent),
            false => (palette().field, palette().ink2),
        };
        fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, fill);
        centred(fb, *r, WIDTHS[i], ink);
    }
}

fn button(fb: &mut PaintBuffer, r: Rect, enabled: bool) -> u32 {
    fb.fill_round(r.x as u32, r.y as u32, r.w as u32, r.h as u32, RADIUS, palette().field);
    if enabled {
        palette().ink2
    } else {
        palette().disabled
    }
}

fn centred(fb: &mut PaintBuffer, r: Rect, s: &str, argb: u32) {
    let s = truncate_to(s, r.w - 8, |t| measure_ttf(t, LABEL_PX));
    let x = r.x + (r.w - measure_ttf(&s, LABEL_PX)) / 2;
    fb.text_ttf(x, r.y + (r.h - line_height(LABEL_PX)) / 2, &s, argb, LABEL_PX);
}

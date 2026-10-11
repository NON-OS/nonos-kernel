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
use nonos_toolkit::font::ttf::{builtin_face, draw_text_with, line_height};

use crate::browser::paint::tokens;
use crate::browser::ui::rect::Rect;

const LOGO: i32 = 32;
const LOGO_RADIUS: u32 = 9;
const LOGO_PX: f32 = 19.0;
const NAME_PX: f32 = 20.0;
const NAME_GAP: i32 = 12;

/// The Ø mark and the NØNOS wordmark, in bold, centred on the brand row.
pub fn paint(r: Rect, fb: &mut PaintBuffer) {
    if r.w < LOGO || r.h <= 0 {
        return;
    }
    let ly = r.y + (r.h - LOGO) / 2;
    fb.fill_round(r.x as u32, ly as u32, LOGO as u32, LOGO as u32, LOGO_RADIUS, tokens::TEAL);
    let mark = "\u{d8}";
    let mx = r.x + (LOGO - measure_ttf(mark, LOGO_PX)) / 2;
    bold(fb, mx, ly + (LOGO - line_height(LOGO_PX)) / 2, mark, tokens::ON_ACCENT, LOGO_PX);
    let ny = r.y + (r.h - line_height(NAME_PX)) / 2;
    bold(fb, r.x + LOGO + NAME_GAP, ny, "N\u{d8}NOS", tokens::INK, NAME_PX);
}

fn bold(fb: &mut PaintBuffer, x: i32, y: i32, s: &str, argb: u32, px: f32) {
    match builtin_face(false, true) {
        Some(face) => {
            let stride = fb.stride_words as usize;
            let (w, h) = (fb.width, fb.height);
            draw_text_with(face, fb.pixels, stride, w, h, x, y, s, argb, px);
        }
        None => {
            fb.text_ttf(x, y, s, argb, px);
        }
    }
}

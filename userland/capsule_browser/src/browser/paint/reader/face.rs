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
use nonos_toolkit::font::ttf::{builtin_face, draw_text_with, measure_with};

/// True when headings can be set in a bold face rather than only larger.
pub fn has_bold() -> bool {
    builtin_face(false, true).is_some()
}

/// The advance of `s` at `px`, in the bold face when `bold` and one exists.
pub fn measure(s: &str, px: f32, bold: bool) -> i32 {
    match builtin_face(false, true).filter(|_| bold) {
        Some(face) => measure_with(face, s, px),
        None => measure_ttf(s, px),
    }
}

/// Draws `s` with its line box top at `y`, matching `measure`.
pub fn draw(fb: &mut PaintBuffer, x: i32, y: i32, s: &str, argb: u32, px: f32, bold: bool) {
    match builtin_face(false, true).filter(|_| bold) {
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

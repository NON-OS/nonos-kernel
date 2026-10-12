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

use crate::browser::omnibox::geometry::TEXT_PX;
use crate::browser::omnibox::LineEdit;

/// The colours a field's text is drawn in: the text and its caret, the
/// hint shown while it is empty, and the selection behind the text.
#[derive(Clone, Copy)]
pub struct FieldInk {
    pub text: u32,
    pub hint: u32,
    pub select: u32,
}

/* One line of field text in the box (x, y, w, h), scrolled left by `off`
 * pixels and clipped to the box: the placeholder when empty, the
 * selection behind the text and a one-pixel caret while focused. */
pub fn field_text(
    fb: &mut PaintBuffer,
    (x, y, w, h): (u32, u32, u32, u32),
    ed: &LineEdit,
    (focused, off): (bool, i32),
    placeholder: &str,
    ink: FieldInk,
) {
    let mut sub = fb.sub(x, y, w, h);
    let line_h = 18;
    let ty = (h as i32 - line_h) / 2;
    let at = |s: &str| sub_measure(s) - off;
    if ed.text.is_empty() {
        sub.text_ttf(0, ty, placeholder, ink.hint, TEXT_PX);
    } else {
        if focused && ed.has_selection() {
            let (a, b) = ed.selection();
            let (xa, xb) = (at(&ed.text[..a]).max(0), at(&ed.text[..b]).min(w as i32));
            if xb > xa {
                sub.fill_rect(xa as u32, ty as u32, (xb - xa) as u32, line_h as u32, ink.select);
            }
        }
        sub.text_ttf(-off, ty, &ed.text, ink.text, TEXT_PX);
    }
    if focused {
        let cx = at(&ed.text[..ed.caret]);
        if cx >= 0 && cx < w as i32 {
            sub.fill_rect(cx as u32, ty as u32, 1, line_h as u32, ink.text);
        }
    }
}

fn sub_measure(s: &str) -> i32 {
    nonos_app_skeleton::measure_ttf(s, TEXT_PX)
}

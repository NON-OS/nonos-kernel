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

use crate::browser::omnibox::geometry::TEXT_PX;
use crate::browser::omnibox::{text_offset, LineEdit};
use crate::browser::paint::tokens::palette;
use crate::browser::paint::{field_text, FieldInk};
use crate::browser::shell::Shell;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::settings_geom::Field;

const INSET: i32 = 12;
const RADIUS: u32 = 10;

/// Where a field drawn in `r` shows its text. Painter and click share it.
pub fn text_box(r: Rect) -> Rect {
    Rect::new(r.x + INSET, r.y, (r.w - 2 * INSET).max(0), r.h)
}

/// How far the text of `ed` is scrolled left in a box `w` wide, so its
/// caret stays in view.
pub fn offset(ed: &LineEdit, w: i32) -> i32 {
    let m = |s: &str| measure_ttf(s, TEXT_PX);
    text_offset(m(&ed.text[..ed.caret]), m(&ed.text), w, 0)
}

/// The character boundary of `text` nearest to `want` pixels into it.
pub fn nearest(text: &str, want: i32) -> usize {
    let mut best = (0usize, want.abs());
    for (i, c) in text.char_indices() {
        let end = i + c.len_utf8();
        let d = (measure_ttf(&text[..end], TEXT_PX) - want).abs();
        if d < best.1 {
            best = (end, d);
        }
    }
    best.0
}

/// Field `f` in `r`: outlined in accent while it has the keyboard.
pub fn paint(fb: &mut PaintBuffer, shell: &Shell, f: Field, r: Rect) {
    let focused = shell.settings.focus == Some(f);
    let (ed, hint) = match f {
        Field::Proxy => (&shell.settings.proxy, "127.0.0.1:9050"),
        Field::Search => (&shell.settings.search, "https://example.org/search?q=%s"),
    };
    let (x, y, w, h) = (r.x as u32, r.y as u32, r.w as u32, r.h as u32);
    fb.fill_round(x, y, w, h, RADIUS, palette().field);
    match focused {
        true => fb.stroke_round(x, y, w, h, RADIUS, 2, palette().accent),
        false => fb.stroke_round(x, y, w, h, RADIUS, 1, palette().edge),
    }
    let b = text_box(r);
    if b.w <= 0 {
        return;
    }
    let ink =
        FieldInk { text: palette().ink, hint: palette().muted, select: palette().accent_soft };
    let area = (b.x as u32, b.y as u32, b.w as u32, b.h as u32);
    field_text(fb, area, ed, (focused, offset(ed, b.w)), hint, ink);
}

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

//! The top strip over the content column: a search field that mirrors the live
//! query buffer, and a right-hand chip naming the mount the library was
//! scanned from. Clicking the field routes to the Search screen.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{pill, ITEM, LABEL, S3, S4, S5, S6};
use crate::ui::paint::{fill, rule, stroke, text_mid, text_right};
use crate::ui::text::tail_to_width;

const FIELD_H: i32 = 34;
const CHIP_W: i32 = 112;

pub fn clear(r: Rect) -> Rect {
    let f = field(r);
    Rect::new(f.right() - 26, f.y, 22, f.h)
}

pub fn field(r: Rect) -> Rect {
    Rect::new(r.x + S5, r.cy() - FIELD_H / 2, (r.w - S5 * 2 - CHIP_W - S6 - S5).min(420), FIELD_H)
}

pub fn topbar(fb: &mut PaintBuffer, icons: &Icons, r: Rect, query: &str, focused: bool) {
    let t = roles();
    let (border, text_2) = (t.border.argb(), t.text_2.argb());
    rule(fb, Rect::new(r.x, r.bottom() - 1, r.w, 1));

    let f = field(r);
    fill(fb, f, pill(f.h), t.sunken.argb());
    if focused {
        fill(fb, f, pill(f.h), t.accent_wash.argb());
    }
    stroke(fb, f, pill(f.h), 1, if focused { t.focus_ring.argb() } else { border });
    icons.centred(fb, Rect::new(f.x + S3, f.y, 22, f.h), 16, Glyph::Search, text_2);
    let tx = f.x + S3 + 22 + S3;
    let text_w = f.right() - tx - S4 - if query.is_empty() { 0 } else { 24 };
    /* A pasted address runs far past the field: its end, the file's name,
     * is what shows. */
    let shown = tail_to_width(query, ITEM, text_w);
    let (label, ink) = if query.is_empty() { ("Search the library", t.quiet) } else { (shown.as_str(), t.text) };
    text_mid(fb, Rect::new(tx, f.y, text_w, f.h), label, ink.argb(), ITEM);
    if !query.is_empty() {
        icons.centred(fb, clear(r), 14, Glyph::Close, text_2);
    }

    /* The folder the library reads, as a label: there is no other source to
     * pick and no notifications to show, so no menu or bell beside it. */
    let chip = Rect::new(r.right() - S6 - CHIP_W, r.cy() - FIELD_H / 2, CHIP_W, FIELD_H);
    fill(fb, chip, pill(chip.h), t.raised.argb());
    stroke(fb, chip, pill(chip.h), 1, border);
    icons.centred(fb, Rect::new(chip.x + S3, chip.y, 20, chip.h), 15, Glyph::Download, t.accent.argb());
    text_right(fb, Rect::new(chip.x, chip.y, chip.w - S4, chip.h), "My music", text_2, LABEL);
}

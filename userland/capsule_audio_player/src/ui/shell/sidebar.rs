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

//! The left rail: brand mark, the navigation destinations and Settings pinned
//! to the foot of the panel. `nav_row` and `settings_row` are the one geometry
//! source, so every hit-test lands on exactly the pill the painter drew.

extern crate alloc;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{cap_h, pill, ITEM, S1, S2, S3, S4, S5, S6, SECTION};
use crate::ui::paint::{fill, rule, stroke, text, text_mid};
use crate::ui::state::{View, NAV};

pub const ROW_H: i32 = 42;
const BRAND_H: i32 = 68;
const GLYPHS: [Glyph; NAV.len()] =
    [Glyph::Home, Glyph::Grid, Glyph::Search, Glyph::Note, Glyph::Download];

pub fn nav_row(r: Rect, i: usize) -> Rect {
    Rect::new(r.x + S3, r.y + BRAND_H + i as i32 * (ROW_H + S1), r.w - S3 * 2, ROW_H)
}

pub fn settings_row(r: Rect) -> Rect {
    Rect::new(r.x + S3, r.bottom() - S5 - ROW_H, r.w - S3 * 2, ROW_H)
}

pub fn row_at(r: Rect, x: i32, y: i32) -> Option<View> {
    if settings_row(r).contains(x, y) {
        return Some(View::Settings);
    }
    (0..NAV.len()).find(|&i| nav_row(r, i).contains(x, y)).map(|i| NAV[i].0)
}

fn entry(fb: &mut PaintBuffer, icons: &Icons, r: Rect, label: &str, g: Glyph, on: bool) {
    let t = roles();
    if on {
        fill(fb, r, pill(r.h), t.accent_wash.argb());
        stroke(fb, r, pill(r.h), 1, t.accent_edge.argb());
    }
    let ink = if on { t.text } else { t.text_2 }.argb();
    icons.centred(fb, Rect::new(r.x + S3, r.y, 30, r.h), 19, g, ink);
    let tx = S3 + 30 + S2;
    text_mid(fb, Rect::new(r.x + tx, r.y, r.w - tx, r.h), label, ink, ITEM);
}

pub fn sidebar(fb: &mut PaintBuffer, icons: &Icons, r: Rect, view: View) {
    let t = roles();
    fill(fb, r, 0, t.surface.argb());
    fill(fb, Rect::new(r.right() - 1, r.y, 1, r.h), 0, t.border.argb());

    let mark = Rect::new(r.x + S5, r.y + S6, 30, 30);
    fill(fb, mark, 9, t.accent_edge.argb());
    fill(fb, mark.inset(5), 5, t.accent.argb());
    text(fb, mark.right() + S3, mark.cy() - cap_h(SECTION), "Resonare", t.text.argb(), SECTION);

    for (i, (v, label)) in NAV.iter().enumerate() {
        entry(fb, icons, nav_row(r, i), label, GLYPHS[i], *v == view);
    }

    let foot = settings_row(r);
    rule(fb, Rect::new(r.x + S5, foot.y - S4, r.w - S5 * 2, 1));
    entry(fb, icons, foot, "Settings", Glyph::Gear, view == View::Settings);
}

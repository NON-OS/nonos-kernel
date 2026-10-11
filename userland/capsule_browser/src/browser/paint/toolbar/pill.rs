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
use nonos_toolkit::font::ttf::line_height;

use crate::browser::omnibox::geometry::{pill_text, Rect as TextBox, NOTICE_W};
use crate::browser::omnibox::Focus;
use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::{field_text, tokens, FieldInk};
use crate::browser::state::{State, View};
use crate::browser::ui::rect::Rect;
use crate::browser::ui::toolbar_geom::ToolbarGeom;

const RADIUS: u32 = 12;
const RING: u32 = 2;
const ICON: i32 = 18;
const ICON_X: i32 = 20;
const NOTICE_PX: f32 = 13.0;
const HINT: &str = "Search or enter address";
const INK: FieldInk =
    FieldInk { text: tokens::INK, hint: tokens::MUTED, select: tokens::ACCENT_SOFT };

/* The rounded address field: a lock on an https page and a search glyph
 * otherwise, the edit text scrolled to keep the caret in its box, a
 * notice when the page was cut short, the route badge at its right end
 * and an accent ring while it has the keyboard. */
pub(super) fn paint(state: &State, g: &ToolbarGeom, fb: &mut PaintBuffer) {
    let p = g.pill;
    if p.w <= 0 || p.h <= 0 {
        return;
    }
    let (x, y, w, h) = (p.x as u32, p.y as u32, p.w as u32, p.h as u32);
    let focused = state.ui.kbd == Focus::Omnibox;
    fb.fill_rect(x, y, w, h, tokens::SURFACE);
    fb.fill_round(x, y, w, h, RADIUS, tokens::FIELD);
    if focused {
        fb.stroke_round(x, y, w, h, RADIUS, RING, tokens::ACCENT);
    }
    let secure = state.view == View::Page && state.ui.current_url.starts_with("https://");
    let lead = if secure { Glyph::Lock } else { Glyph::Search };
    glyph::draw(fb, lead, p.x + ICON_X, p.y + p.h / 2, ICON, tokens::MUTED);
    let bar = Rect::new(0, 0, fb.width as i32, fb.height as i32);
    let t = pill_text(bar, state.ui.truncated);
    let at = (focused, state.ui.text_off);
    field_text(fb, (t.x, t.y, t.w, t.h), &state.ui.omnibox, at, HINT, INK);
    if state.ui.truncated {
        notice(fb, t);
    }
    super::route::paint(state, g.route, fb);
}

/* The truncated-page notice, in the room the text leaves at its right end. */
fn notice(fb: &mut PaintBuffer, t: TextBox) {
    let mut sub = fb.sub(t.x + t.w + 8, t.y, NOTICE_W - 8, t.h);
    let ty = (t.h as i32 - line_height(NOTICE_PX)) / 2;
    sub.text_ttf(0, ty, "page truncated", tokens::WARN, NOTICE_PX);
}

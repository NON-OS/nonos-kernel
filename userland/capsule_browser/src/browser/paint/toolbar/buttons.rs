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

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens;
use crate::browser::state::{State, View};
use crate::browser::ui::rect::Rect;
use crate::browser::ui::toolbar_geom::ToolbarGeom;

const ICON: i32 = 20;

/* Back is lit on the home page when there is a page to return to. */
pub(super) fn paint(state: &State, g: &ToolbarGeom, fb: &mut PaintBuffer) {
    let h = &state.ui.history;
    let back = h.can_back() || (state.view == View::Home && h.current().is_some());
    icon(fb, g.back, Glyph::Back, tone(back));
    icon(fb, g.fwd, Glyph::Forward, tone(h.can_forward()));
    let reload = if state.loading() { Glyph::Close } else { Glyph::Reload };
    icon(fb, g.reload, reload, tokens::INK2);
    icon(fb, g.home, Glyph::Home, tokens::INK2);
    icon(fb, g.menu, Glyph::More, tokens::INK2);
}

fn tone(enabled: bool) -> u32 {
    if enabled {
        tokens::INK2
    } else {
        tokens::DISABLED
    }
}

fn icon(fb: &mut PaintBuffer, r: Rect, g: Glyph, argb: u32) {
    glyph::draw(fb, g, r.x + r.w / 2, r.y + r.h / 2, ICON, argb);
}

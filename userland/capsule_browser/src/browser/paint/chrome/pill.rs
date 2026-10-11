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

use crate::browser::omnibox::geometry::{pill_rect, pill_text_w, NOTICE_W, PILL_TEXT_X};
use crate::browser::omnibox::Focus;
use crate::browser::paint::chrome::constants::{ACCENT, BORDER, DIM, FIELD_BG, TOOLBAR_BG, WARN};
use crate::browser::state::State;

/* The address pill: the edit text clipped to its box, and on a page the
 * parser had to cut short a notice at its right end. It repaints on its own
 * for every keystroke, so typing redraws this and nothing else. */
pub fn pill(state: &State, fb: &mut PaintBuffer) {
    let r = pill_rect(fb.width);
    let (l, w) = (r.x, r.w);
    let focused = state.ui.kbd == Focus::Omnibox;
    fb.fill_rect(l, r.y, w, 32, if focused { ACCENT } else { BORDER });
    fb.fill_rect(l + 1, r.y + 1, w.saturating_sub(2), 30, FIELD_BG);
    for (cx, cy) in [(l, r.y), (l + w.saturating_sub(2), r.y), (l, r.y + 30)] {
        fb.fill_rect(cx, cy, 2, 2, TOOLBAR_BG);
    }
    fb.fill_rect(l + w.saturating_sub(2), r.y + 30, 2, 2, TOOLBAR_BG);
    fb.fill_rect(l + 10, r.y + 12, 8, 8, DIM);
    fb.fill_rect(l + 12, r.y + 14, 4, 4, FIELD_BG);
    let notice = state.ui.truncated;
    /* The network the next request leaves through stays in view at the
     * field's right end, so the reader never opens a panel to learn whether
     * the address is hidden; the edit text stops short of it. */
    let net = crate::browser::settings::network_line(state);
    let nw = (net.len() as u32) * 7 + 16;
    let tw = pill_text_w(fb.width, notice).saturating_sub(nw);
    let boxed = (l + PILL_TEXT_X, r.y + 1, tw, 30);
    let hint = "Search or enter address";
    super::field_text(fb, boxed, &state.ui.omnibox, focused, state.ui.text_off, hint);
    if notice {
        let nx = (l + PILL_TEXT_X + tw) as i32 + 8;
        let mut sub = fb.sub(nx as u32, r.y + 1, NOTICE_W - 8, 30);
        sub.text_ttf(0, 6, "page truncated", WARN, 13.0);
    }
    let nx = (l + w).saturating_sub(nw);
    fb.fill_rect(nx.saturating_sub(8), r.y + 1, nw + 4, 30, FIELD_BG);
    fb.text_ttf(nx as i32, r.y as i32 + 8, &net, ACCENT, 13.0);
}

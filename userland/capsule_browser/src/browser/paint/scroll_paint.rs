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

use crate::browser::omnibox::geometry::BUBBLE_BAND;
use crate::browser::omnibox::{band_safe, blit_plan, guarded, Blit};
use crate::browser::state::State;

use super::{blit_rows::blit_rows, bubble, rows::paint_rows};

/* Repaint a scroll by moving the page pixels still in view and drawing
 * only the rows that came into view, plus the bottom band that holds the
 * bubble and the window's rounded corners. Pages with fixed or sticky
 * boxes move differently from their pixels and take the full repaint, as
 * does a move of a whole viewport or more. Returns false to ask for it. */
pub(super) fn shift(state: &mut State, fb: &mut PaintBuffer) -> bool {
    let Some(doc) = state.box_doc.as_ref() else {
        return false;
    };
    if !band_safe(doc.frags.iter().map(|f| (f.fixed, f.sticky.is_some()))) {
        return false;
    }
    let view_h = fb.height;
    let plan = blit_plan(state.track.painted_scroll, state.scroll, view_h);
    if plan == Blit::Same {
        return true;
    }
    let Some(s) = guarded(plan, view_h, BUBBLE_BAND) else {
        return false;
    };
    blit_rows(fb, s.src_y, s.dst_y, s.rows);
    state.track.painted_scroll = state.scroll;
    for (a, b) in s.bands {
        if a < b && !paint_rows(state, fb, a, b) {
            return false;
        }
    }
    bubble::paint(state, fb);
    true
}

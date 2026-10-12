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

use nonos_toolkit::decorations::Rect;

use crate::browser::omnibox::geometry::{band_commit, Rect as Area, BUBBLE_BAND};
use crate::browser::omnibox::{rect_of, Damage};
use crate::browser::paint::band_rows;
use crate::browser::state::State;

/* Hand the runner the rect this repaint must cover, and remember which
 * parts the paint that follows draws. A repaint with nothing recorded, a
 * size not yet known or an empty rect draws everything. */
pub(super) fn take(state: &mut State) -> Option<Rect> {
    let mut parts = core::mem::take(&mut state.track.damage);
    state.track.painted_gen = state.track.paint_gen;
    if parts.is_empty() || state.viewport_w == 0 {
        parts = Damage::FULL;
    }
    let r = rect_of(parts, &state.layout).map(|r| match parts.has(Damage::BUBBLE) {
        true => r.union(bubble_paint(state, Area::from(state.layout.content))),
        false => r,
    });
    let Some(r) = r.filter(|r| r.w != 0 && r.h != 0) else {
        state.track.painting = Damage::FULL;
        return None;
    };
    state.track.painting = parts;
    Some(Rect { x: r.x, y: r.y, w: r.w, h: r.h })
}

/* What the bubble repaint draws in the page area `page`: its band grown
 * over the boxes crossing it, or the whole page when the band cannot be
 * painted alone. The commit covers it all, so no pixel it draws is left
 * out of the screen. */
fn bubble_paint(state: &State, page: Area) -> Area {
    let view_h = page.h as i32;
    band_commit(band_rows(state, view_h - BUBBLE_BAND as i32, view_h, view_h), page)
}

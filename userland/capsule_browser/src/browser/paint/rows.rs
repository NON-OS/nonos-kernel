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

use crate::browser::state::State;

use super::band::band_rows;

/* Repaint viewport rows [y0, y1) as a full paint does: the page painter
 * draws into band_rows with the scroll moved by its top. False when the
 * band cannot be painted alone (band_rows is None). */
pub(super) fn paint_rows(state: &mut State, fb: &mut PaintBuffer, y0: u32, y1: u32) -> bool {
    let view_h = fb.height as i32;
    let Some((a, b)) = band_rows(state, y0 as i32, y1 as i32, view_h) else {
        return false;
    };
    if b <= a {
        return true;
    }
    let mut sub = fb.sub(0, a as u32, fb.width, (b - a) as u32);
    state.scroll = state.scroll.saturating_add(a as u32);
    if let Some(doc) = state.box_doc.as_ref() {
        super::box_page::paint(state, doc, &mut sub);
    }
    state.scroll = state.scroll.saturating_sub(a as u32);
    true
}

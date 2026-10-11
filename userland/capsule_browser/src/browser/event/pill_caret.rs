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

use nonos_app_skeleton::measure_ttf;

use crate::browser::omnibox::geometry::{pill_rect, PILL_TEXT_X, TEXT_PX};
use crate::browser::state::State;

/* Put the address bar caret at the character boundary nearest to the click
 * at `x`, taking the text's horizontal scroll into account. */
pub(super) fn place_caret(state: &mut State, x: i32) {
    let origin =
        (pill_rect(state.layout.toolbar.w as u32).x + PILL_TEXT_X) as i32 - state.ui.text_off;
    let want = x - origin;
    let ed = &mut state.ui.omnibox;
    let mut best = (0usize, want.abs());
    for (i, c) in ed.text.char_indices() {
        let end = i + c.len_utf8();
        let d = (measure_ttf(&ed.text[..end], TEXT_PX) - want).abs();
        if d < best.1 {
            best = (end, d);
        }
    }
    ed.caret = best.0;
    ed.anchor = best.0;
    state.fit_text();
    state.mark_omnibox();
}

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

use crate::browser::layout::boxmodel::{BoxDocument, Fragment};
use crate::browser::layout::hit_screen::frag_screen_y;
use crate::browser::state::State;

use super::canvas::paint_canvas;

pub(super) const TOP: i32 = 0;

pub fn paint(state: &State, doc: &BoxDocument, fb: &mut PaintBuffer) {
    paint_canvas(state, doc, fb);
    let bottom = fb.height as i32;
    /* A fully transparent fragment (opacity 0, a transform that flattened
     * it, a clip-path that leaves nothing) paints nothing at all. */
    let mut owner: Option<&Fragment> = None;
    for f in doc.frags.iter().filter(|f| f.alpha != 0) {
        let sy = TOP + frag_screen_y(f.y, f.fixed, f.sticky, state.scroll as i32);
        if sy + f.h < TOP || sy > bottom {
            continue;
        }
        /* Drawn inside a gradient-masked box: through its mask. */
        if f.fade_by != 0 {
            if owner.is_none_or(|o| o.node != f.fade_by) {
                owner = doc.frags.iter().find(|o| o.node == f.fade_by && o.fade != 0);
            }
            if let Some(o) = owner {
                super::masked::paint_masked(state, fb, f, o);
                continue;
            }
        }
        super::tinted::paint_one(state, fb, f, sy, bottom);
    }
}

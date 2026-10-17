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
use nonos_toolkit::widgets::{Pill, Rect, State as Look};

use crate::pm::state::{State, FILTERS};

use super::hit::Target;
use super::hover_look::pointed;
use super::metrics::{CHIP_GAP, CHIP_H};
use super::text;

#[path = "chips_geom.rs"]
mod chips_geom;

pub use chips_geom::{at, origin, width};

/// The head band's filter row: each chip a toolkit pill in the box `at`
/// hit-tests, the pill being exactly as wide as `chip_w`. The active one is
/// selected, so it wears the accent wash and edge the sidebar's current row
/// wears, and the one under the pointer draws its hover and press.
pub fn paint(fb: &mut PaintBuffer, state: &State) {
    let Some(mut x) = origin(fb.width, state.screen) else {
        return;
    };
    let y = chips_geom::top();
    for &filter in FILTERS.iter() {
        let w = chips_geom::chip_w(filter);
        let look = pointed(state, |t| t == Target::Filter(filter));
        let look = Look { selected: filter == state.filter, ..look };
        let pill = Pill::new(text::valid(filter.label())).state(look);
        pill.draw(fb, Rect { x, y, w, h: CHIP_H });
        x += w + CHIP_GAP;
    }
}

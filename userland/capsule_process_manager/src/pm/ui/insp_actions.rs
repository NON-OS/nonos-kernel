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
use nonos_toolkit::widgets::{Button, Kind, Rect, State as Look};

use crate::pm::state::State;

use super::hit::Target;
use super::hover_look::pointed;
use super::insp_geom::btn;

// End Process ends the process at once: the kernel runs no handler for the
// signal, so there is no gentler and no harder way to offer. It takes two
// presses, so the toolkit's danger button is armed, and fills, while the first
// waits for the second. A process this monitor will not end gets no button
// that looks as if it would: a disabled one says so, and end_selected still
// refuses. Both are drawn in the box `btn` gives the hit test.
/// End Process draws the pointer's hover and press; the protected note does not.
pub fn paint(fb: &mut PaintBuffer, state: &State, protected: bool, armed: bool) {
    let (x, y, w, h) = btn(fb.width, fb.height);
    let at = Rect { x, y, w, h };
    if protected {
        let look = Look { disabled: true, ..Look::default() };
        Button::new("Protected: cannot be ended here").state(look).draw(fb, at);
        return;
    }
    let look = Look { selected: armed, ..pointed(state, |t| t == Target::EndProcess) };
    Button::new("End Process").kind(Kind::Danger).state(look).draw(fb, at);
}

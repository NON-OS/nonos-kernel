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

use crate::clock::controls::Target;
use crate::clock::state::State;
use crate::clock::tabs::{bar, strip};

/// The shared tab strip across the bar, the hovered tab lit.
pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let hovered = match state.hover {
        Some(Target::Tab(i)) => Some(i),
        _ => None,
    };
    strip(state.tab).hovered(hovered).draw(fb, bar(fb.width));
}

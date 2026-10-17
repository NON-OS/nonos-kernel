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

//! The hover and press a widget draws, from the pointer and the targets that
//! are the widget's own.

use nonos_toolkit::widgets::State as Look;

use crate::pm::state::State;

use super::hit::Target;
use super::hover::target_at;

/// The look the pointer gives a widget, where `mine` says which targets are
/// its own. Only a widget under the hover asks the pointer, so a paint walks
/// the geometry once more at most, and a press shows only where it began.
pub fn pointed(state: &State, mine: impl Fn(Target) -> bool) -> Look {
    if !state.hover.is_some_and(&mine) {
        return Look::default();
    }
    state.pointer.state(|x, y| target_at(state, x, y).is_some_and(&mine))
}

/// The same, `focused` when the keyboard is on the widget, which is what
/// draws the shared focus ring.
pub fn look(state: &State, mine: impl Fn(Target) -> bool, focused: bool) -> Look {
    Look { focused, ..pointed(state, mine) }
}

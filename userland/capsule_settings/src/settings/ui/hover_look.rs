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

use crate::settings::state::{searching, view_h, State};

use super::bytes::as_str;
use super::hover::target_at;
use super::results;
use super::target::Target;

/// The look the pointer gives a widget, where `mine` says which targets are
/// its own. Only a widget under the hover asks the pointer, so a paint walks
/// the geometry once more at most, and a press shows only where it began.
pub fn pointed(state: &State, mine: impl Fn(Target) -> bool) -> Look {
    if !mine(state.hover) {
        return Look::default();
    }
    let (h, found) = (view_h(state), found(state));
    state.pointer.state(|x, y| mine(target_at(state, x, y, h, found)))
}

/// The same, `focused` when the keyboard cursor is on the widget, which is
/// what draws the shared focus ring.
pub fn look(state: &State, mine: impl Fn(Target) -> bool, focused: bool) -> Look {
    Look { focused, ..pointed(state, mine) }
}

/// The result count while a search is on screen, which turns the pane's
/// targets into result rows.
pub fn found(state: &State) -> Option<usize> {
    searching(state).then(|| results::count(as_str(state.search.as_slice())))
}

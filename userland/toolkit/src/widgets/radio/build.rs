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

//! The radio and the builders that set it up.

use crate::widgets::State;

/// One choice of a group. `selected` is its value; `State::selected` is
/// ignored.
#[derive(Clone, Copy, Debug, Default)]
pub struct Radio<'a> {
    pub(super) selected: bool,
    pub(super) label: &'a str,
    pub(super) state: State,
}

impl<'a> Radio<'a> {
    /// A radio showing `selected`, with no label.
    pub fn new(selected: bool) -> Self {
        Radio { selected, label: "", state: State::default() }
    }

    /// The label drawn to the right of the ring.
    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    /// The state the app reports. `selected` is ignored, since the value
    /// given to `new` is the choice.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

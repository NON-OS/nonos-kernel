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

//! The switch and the builders that set it up.

use crate::widgets::State;

/// An on/off switch. `on` is its value; `State::selected` is ignored.
#[derive(Clone, Copy, Debug, Default)]
pub struct Switch {
    pub(super) on: bool,
    pub(super) state: State,
}

impl Switch {
    /// A switch showing `on`.
    pub fn new(on: bool) -> Self {
        Switch { on, state: State::default() }
    }

    /// The state the app reports. `selected` is ignored, since `on` is the
    /// value.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

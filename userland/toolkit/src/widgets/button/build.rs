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

//! The button and the builders that set it up.

use super::Kind;
use crate::widgets::State;

/// A push button with a one-line label.
#[derive(Clone, Copy, Debug)]
pub struct Button<'a> {
    pub(super) label: &'a str,
    pub(super) kind: Kind,
    pub(super) state: State,
}

impl<'a> Button<'a> {
    /// A `Secondary` button showing `label`.
    pub fn new(label: &'a str) -> Self {
        Button { label, kind: Kind::default(), state: State::default() }
    }

    /// The kind of button, which decides its colours.
    pub fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    /// The state the app reports. `selected` arms a `Danger` button and is
    /// ignored by the other kinds.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

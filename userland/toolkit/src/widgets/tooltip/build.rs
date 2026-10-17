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

//! The tooltip and the builders that set it up.

use crate::widgets::State;

/// A one-line label in a small box beside an anchor, such as a toolbar button.
#[derive(Clone, Copy, Debug)]
pub struct Tooltip<'a> {
    pub(super) text: &'a str,
    pub(super) below: bool,
    pub(super) state: State,
}

impl<'a> Tooltip<'a> {
    /// A tooltip showing `text`, which prefers to open above its anchor.
    pub fn new(text: &'a str) -> Self {
        Tooltip { text, below: false, state: State::default() }
    }

    /// Prefers opening below the anchor instead of above it.
    pub fn below(mut self) -> Self {
        self.below = true;
        self
    }

    /// The state the app reports. Only `disabled` changes the look, drawing
    /// the text in `disabled`. A tooltip takes no pointer or focus, so the
    /// other states change nothing.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

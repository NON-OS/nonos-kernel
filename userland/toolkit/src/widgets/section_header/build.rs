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

//! The section header and the builders that set it up.

use crate::widgets::State;

/// A title with an optional note under it. It is not clickable, so it has no
/// hit test.
#[derive(Clone, Copy, Debug)]
pub struct SectionHeader<'a> {
    pub(super) title: &'a str,
    pub(super) note: Option<&'a str>,
    pub(super) state: State,
}

impl<'a> SectionHeader<'a> {
    /// A title with no note.
    pub fn new(title: &'a str) -> Self {
        SectionHeader { title, note: None, state: State::default() }
    }

    /// A muted line under the title.
    pub fn note(mut self, note: &'a str) -> Self {
        self.note = Some(note);
        self
    }

    /// The state the app reports. Only `disabled` changes the look.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

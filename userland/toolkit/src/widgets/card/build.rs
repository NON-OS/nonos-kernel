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

//! The card and the builders that set it up.

use crate::widgets::State;

/// A rounded, outlined panel that fills the Rect it is given, with an
/// optional head of a title and a note under it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Card<'a> {
    pub(super) title: Option<&'a str>,
    pub(super) note: Option<&'a str>,
    pub(super) state: State,
}

impl<'a> Card<'a> {
    /// A bare card with no head.
    pub fn new() -> Self {
        Card { title: None, note: None, state: State::default() }
    }

    /// The title in the head. Without one the card has no head.
    pub fn title(mut self, title: &'a str) -> Self {
        self.title = Some(title);
        self
    }

    /// A muted line under the title. Ignored when there is no title.
    pub fn note(mut self, note: &'a str) -> Self {
        self.note = Some(note);
        self
    }

    /// The state the app reports.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

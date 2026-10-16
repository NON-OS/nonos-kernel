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

//! The pill and the builders that set it up.

use crate::widgets::{State, Tone};

/// A status pill with a one-line label.
#[derive(Clone, Copy, Debug)]
pub struct Pill<'a> {
    pub(super) label: &'a str,
    pub(super) tone: Tone,
    pub(super) dot: bool,
    pub(super) state: State,
}

impl<'a> Pill<'a> {
    /// A `Plain` pill showing `label`, with no dot.
    pub fn new(label: &'a str) -> Self {
        Pill { label, tone: Tone::Plain, dot: false, state: State::default() }
    }

    /// The status the pill shows, which colours the dot, or the label when
    /// there is no dot.
    pub fn tone(mut self, tone: Tone) -> Self {
        self.tone = tone;
        self
    }

    /// Puts a status dot in the tone's colour before the label.
    pub fn dot(mut self) -> Self {
        self.dot = true;
        self
    }

    /// The state the app reports.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

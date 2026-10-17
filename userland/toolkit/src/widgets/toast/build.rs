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

//! The toast and the builders that set it up.

use crate::widgets::{Button, Kind, State, Tone};

/// A notice panel: a bar in its tone, up to two lines of text and an
/// optional action button at the right.
#[derive(Clone, Copy, Debug)]
pub struct Toast<'a> {
    pub(super) text: &'a str,
    pub(super) tone: Tone,
    pub(super) action: &'a str,
    pub(super) state: State,
}

impl<'a> Toast<'a> {
    /// A `Plain` toast showing `text`, with no action.
    pub fn new(text: &'a str) -> Self {
        Toast { text, tone: Tone::Plain, action: "", state: State::default() }
    }

    /// The status the toast shows, which colours its bar. The shell's Info,
    /// Warn and Error are `Accent`, `Warn` and `Danger`.
    pub fn tone(mut self, tone: Tone) -> Self {
        self.tone = tone;
        self
    }

    /// The label of the action button at the right. An empty label draws no
    /// button, and then nothing is hit.
    pub fn action(mut self, label: &'a str) -> Self {
        self.action = label;
        self
    }

    /// The state the app reports, which the action button draws: `hit` is
    /// true only on the button, so `Pointer::state` given that hit test
    /// yields the button's hover and press, and focus rings the button.
    /// Disabled also draws the text and bar in `disabled`. Selected changes
    /// nothing, and with no action only disabled changes the look.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }

    /// The `Button` the action is drawn as: `Plain`, in the toast's state.
    pub(super) fn button(&self) -> Button<'a> {
        Button::new(self.action).kind(Kind::Plain).state(self.state)
    }
}

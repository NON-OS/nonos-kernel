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

//! The dialog and the builders that set out what it says.

use crate::widgets::{Kind, State, Tone};

/// A panel centred over a scrim that covers the box it is drawn in.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dialog<'a> {
    pub(super) title: &'a str,
    pub(super) body: &'a str,
    pub(super) note: &'a str,
    pub(super) tone: Tone,
    pub(super) buttons: &'a [(&'a str, Kind)],
    pub(super) focus: Option<usize>,
    pub(super) hovered: Option<usize>,
    pub(super) pressed: Option<usize>,
    pub(super) state: State,
}

impl<'a> Dialog<'a> {
    /// A dialog headed `title`, with no body, note or buttons, and no button
    /// focused.
    pub fn new(title: &'a str) -> Self {
        Dialog { title, ..Dialog::default() }
    }

    /// The text under the title. It wraps to as many lines as the panel
    /// holds, at most `DIALOG_LINES`, and the last is cut with `…` when more
    /// would follow.
    pub fn body(mut self, text: &'a str) -> Self {
        self.body = text;
        self
    }

    /// One line under the body in `tone`'s ink, such as a warning that the
    /// list above was cut, itself cut with `…` to fit. It keeps its place
    /// before the body's last lines when the panel is short.
    pub fn note(mut self, text: &'a str, tone: Tone) -> Self {
        self.note = text;
        self.tone = tone;
        self
    }

    /// The buttons, as a label and a kind each, in a row at the bottom
    /// right, first to last from left to right. `hit` names them by index.
    pub fn buttons(mut self, buttons: &'a [(&'a str, Kind)]) -> Self {
        self.buttons = buttons;
        self
    }
}

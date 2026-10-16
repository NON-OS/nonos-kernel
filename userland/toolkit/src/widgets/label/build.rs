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

//! The label and the builders that set it up.

use super::Align;
use crate::design::text_role::TextRole;
use crate::widgets::{Ink, State};

/// One line of text. A label is not clickable, so it has no hit test.
#[derive(Clone, Copy, Debug)]
pub struct Label<'a> {
    pub(super) text: &'a str,
    pub(super) role: TextRole,
    pub(super) ink: Ink,
    pub(super) align: Align,
    pub(super) state: State,
}

impl<'a> Label<'a> {
    /// Body text in the text ink, aligned left.
    pub fn new(text: &'a str) -> Self {
        Label {
            text,
            role: TextRole::Body,
            ink: Ink::Text,
            align: Align::Left,
            state: State::default(),
        }
    }

    /// The text size.
    pub fn role(mut self, role: TextRole) -> Self {
        self.role = role;
        self
    }

    /// The colour the text is drawn in.
    pub fn ink(mut self, ink: Ink) -> Self {
        self.ink = ink;
        self
    }

    /// Where the text sits across its box.
    pub fn align(mut self, align: Align) -> Self {
        self.align = align;
        self
    }

    /// The state the app reports. Only `disabled` changes the look.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

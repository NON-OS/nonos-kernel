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

//! The row and the builders that set it up.

use crate::widgets::{Ink, State};

/// A list row with a label, and optionally a note, a value, room for an app's
/// own control and a chevron. It draws no hairline; put a `Separator` between
/// rows.
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    pub(super) label: &'a str,
    pub(super) value: Option<&'a str>,
    pub(super) note: Option<&'a str>,
    pub(super) chevron: bool,
    pub(super) value_ink: Ink,
    pub(super) trailing: u32,
    pub(super) state: State,
}

impl<'a> Row<'a> {
    /// A row with only a label.
    pub fn new(label: &'a str) -> Self {
        Row {
            label,
            value: None,
            note: None,
            chevron: false,
            value_ink: Ink::Text2,
            trailing: 0,
            state: State::default(),
        }
    }

    /// A value shown right-aligned at the row's right end.
    pub fn value(mut self, value: &'a str) -> Self {
        self.value = Some(value);
        self
    }

    /// A muted line under the label. It makes the row taller.
    pub fn note(mut self, note: &'a str) -> Self {
        self.note = Some(note);
        self
    }

    /// A disclosure chevron at the far right, for a row that opens a page.
    pub fn chevron(mut self) -> Self {
        self.chevron = true;
        self
    }

    /// The state the app reports.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

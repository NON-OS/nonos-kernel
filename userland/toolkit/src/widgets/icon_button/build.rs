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

//! The icon button and the builders that set it up.

use crate::icons::IconId;
use crate::widgets::{Button, Kind, State};

/// A button showing an icon, with an optional one-line label after it.
#[derive(Clone, Copy, Debug)]
pub struct IconButton<'a> {
    pub(super) icon: IconId,
    pub(super) label: &'a str,
    pub(super) kind: Kind,
    pub(super) state: State,
}

impl<'a> IconButton<'a> {
    /// A `Plain` button showing `icon`, with no label: the toolbar look.
    pub fn new(icon: IconId) -> Self {
        IconButton { icon, label: "", kind: Kind::Plain, state: State::default() }
    }

    /// The kind of button, which decides its colours as it does a `Button`'s.
    pub fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    /// The label drawn after the icon. An empty label leaves the button
    /// square.
    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    /// The state the app reports. `selected` arms a `Danger` button and is
    /// ignored by the other kinds, as on a `Button`.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }

    /// The `Button` this one's body is drawn as, with no label of its own.
    pub(super) fn body(&self) -> Button<'static> {
        Button::new("").kind(self.kind).state(self.state)
    }
}

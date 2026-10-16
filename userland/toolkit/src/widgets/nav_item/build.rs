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

//! The navigation item and the builders that set it up.

use crate::icons::IconId;
use crate::widgets::State;

/// A sidebar entry with a one-line label and an optional icon before it.
#[derive(Clone, Copy, Debug)]
pub struct NavItem<'a> {
    pub(super) label: &'a str,
    pub(super) icon: Option<IconId>,
    pub(super) active: bool,
    pub(super) state: State,
}

impl<'a> NavItem<'a> {
    /// An inactive item showing `label`, with no icon.
    pub fn new(label: &'a str) -> Self {
        NavItem { label, icon: None, active: false, state: State::default() }
    }

    /// The icon drawn before the label, in the label's ink.
    pub fn icon(mut self, id: IconId) -> Self {
        self.icon = Some(id);
        self
    }

    /// Whether this item's page is the one on show.
    pub fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// The state the app reports. `selected` is ignored; use `active`.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

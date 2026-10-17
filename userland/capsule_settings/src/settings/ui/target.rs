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

//! What the pointer is over: the thing a click there acts on, named so the
//! panel can tell a move inside one target from a move to the next.

use crate::settings::section::Section;

/// What lies under the pointer.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Target {
    #[default]
    None,
    /// A sidebar entry.
    Nav(Section),
    /// A row's label, by the row's index among the section's editable rows.
    Row(usize),
    /// The control column of that row.
    Control(usize),
    /// A found or saved network's row, counted as `Hit::Network` counts them.
    Network(usize),
    /// The empty scan row, whose "Scan" asks for one.
    Scan,
    /// A search result's row.
    Result(usize),
    /// The search field in the titlebar.
    Search,
}

impl Target {
    /// Whether this is the editable row `index`, its label or its control.
    pub fn on_row(self, index: usize) -> bool {
        matches!(self, Target::Row(i) | Target::Control(i) if i == index)
    }
}

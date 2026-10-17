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

//! The builders that light one row, each by its index in the whole list.

use super::Table;

impl Table<'_> {
    /// The row the app has chosen. It gets an accent wash.
    pub fn selected(mut self, index: Option<usize>) -> Self {
        self.selected = index;
        self
    }

    /// The row under the pointer, or the one the arrow keys have reached. It
    /// gets a hover wash.
    pub fn hovered(mut self, index: Option<usize>) -> Self {
        self.hovered = index;
        self
    }

    /// The row held down. Its ground takes the held fill.
    pub fn pressed(mut self, index: Option<usize>) -> Self {
        self.pressed = index;
        self
    }

    /// Whether the row with whole-list index `index` is `lit`, which a
    /// disabled table never is.
    pub(super) fn is(&self, lit: Option<usize>, index: usize) -> bool {
        !self.state.disabled && lit == Some(index)
    }
}

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

//! The row's finer options: the value's ink, and room at the right end for a
//! control the app draws itself.

use super::Row;
use crate::widgets::Ink;

impl Row<'_> {
    /// The value's ink, `Ink::Text2` unless set. A disabled row still draws
    /// it in the disabled ink.
    pub fn value_ink(mut self, ink: Ink) -> Self {
        self.value_ink = ink;
        self
    }

    /// Keeps a box `w` drawing pixels wide free at the right, left of the
    /// chevron, for a switch, slider or pill the app draws itself. The value
    /// moves to the box's left and the label is cut to what remains.
    /// `trailing_rect` gives the box.
    pub fn trailing(mut self, w: u32) -> Self {
        self.trailing = w;
        self
    }
}

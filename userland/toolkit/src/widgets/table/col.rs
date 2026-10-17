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

//! A table's column: its title, its width and which side its cells keep to.

/// How wide a column is: a fixed width in logical pixels, or a share of what
/// the fixed columns leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Width {
    Fixed(u32),
    Share(u32),
}

/// One column of a table: a title for its header and a width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Col<'a> {
    pub(super) title: &'a str,
    pub(super) width: Width,
    pub(super) right: bool,
}

impl<'a> Col<'a> {
    /// A column headed `title`, taking one share of the room left over, its
    /// cells kept to the left.
    pub const fn new(title: &'a str) -> Self {
        Col { title, width: Width::Share(1), right: false }
    }

    /// A fixed width in logical pixels, scaled when drawn.
    pub const fn fixed(mut self, px: u32) -> Self {
        self.width = Width::Fixed(px);
        self
    }

    /// `n` shares of the room the fixed columns leave. A column with no
    /// share of it gets none.
    pub const fn share(mut self, n: u32) -> Self {
        self.width = Width::Share(n);
        self
    }

    /// Keeps the title and cells to the right, so the digits of a numeric
    /// column line up.
    pub const fn right(mut self) -> Self {
        self.right = true;
        self
    }
}

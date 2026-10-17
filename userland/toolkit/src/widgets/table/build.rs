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

//! The table and the builders that set what it holds.

use super::Col;
use crate::widgets::State;

/// A header of column titles over rows of cells, drawing only the rows it
/// is given.
#[derive(Clone, Copy, Debug)]
pub struct Table<'a> {
    pub(super) cols: &'a [Col<'a>],
    pub(super) rows: &'a [&'a [&'a str]],
    pub(super) first: usize,
    pub(super) sort: Option<(usize, bool)>,
    pub(super) selected: Option<usize>,
    pub(super) hovered: Option<usize>,
    pub(super) pressed: Option<usize>,
    pub(super) state: State,
}

impl<'a> Table<'a> {
    /// A table of `cols`, left to right, with no rows, no sort and nothing
    /// lit.
    pub fn new(cols: &'a [Col<'a>]) -> Self {
        let (selected, hovered, pressed) = (None, None, None);
        let (rows, first, sort, state) = (&[][..], 0, None, State::default());
        Table { cols, rows, first, sort, selected, hovered, pressed, state }
    }

    /// The rows to draw, top to bottom, each a cell per column. Pass only
    /// the rows on screen: a cell past the last column is not drawn, and a
    /// row short of cells leaves the rest blank.
    pub fn rows(mut self, rows: &'a [&'a [&'a str]]) -> Self {
        self.rows = rows;
        self
    }

    /// The index of the first given row in the whole list. Every other
    /// index the table takes or gives counts in the whole list too, so a
    /// row keeps its stripe, selection and hit as the list scrolls.
    pub fn first(mut self, index: usize) -> Self {
        self.first = index;
        self
    }

    /// Orders the list by column `col`, smallest first when `up`. Its header
    /// shows the order with a chevron.
    pub fn sort(mut self, col: usize, up: bool) -> Self {
        self.sort = Some((col, up));
        self
    }

    /// The state the app reports for the whole table. Only `disabled` is
    /// read: it draws every ink in `disabled`, with no row lit, and nothing
    /// is hit. Selection, hover and press belong to one row each.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}

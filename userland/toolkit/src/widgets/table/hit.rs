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

//! What a point on a table names, from `parts`.

use super::Table;
use crate::decorations::Rect;
use crate::widgets::rect::contains;

/// The part of a table a point is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    /// The header of the column with this index, to sort by.
    Header(usize),
    /// The cell in column `col` of the row with whole-list index `row`.
    Row {
        /// The row's index in the whole list, counted from `first`.
        row: usize,
        /// The column's index.
        col: usize,
    },
}

impl Table<'_> {
    /// The header or cell under the point, if any. The hairline under the
    /// header, the body below the last row, every point outside `at` and
    /// every point of a disabled table give `None`. `at` and the point use
    /// `draw`'s coordinates: content coordinates when drawn through
    /// `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> Option<Cell> {
        if self.state.disabled {
            return None;
        }
        let p = self.parts(at);
        let col = |band: Rect| {
            let cell = |s: &super::geometry::Span| Rect { x: s.x, w: s.w, ..band };
            p.cols.iter().position(|s| contains(cell(s), x, y))
        };
        if contains(p.head, x, y) {
            return col(p.head).map(Cell::Header);
        }
        let k = p.rows.iter().position(|r| contains(*r, x, y))?;
        let row = self.first.saturating_add(k);
        col(p.rows[k]).map(|col| Cell::Row { row, col })
    }
}

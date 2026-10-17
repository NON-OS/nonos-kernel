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

//! A table's size, and the measures its parts share.

use super::col::Width;
use super::Table;
use crate::design::scale::scale;
use crate::design::size::{TABLE_COL_MIN, TABLE_ROW_H};
use crate::design::text_role::TextRole;

impl Table<'_> {
    /// Across: each fixed column's width and `TABLE_COL_MIN` for each shared
    /// one. Down: the header, the hairline under it and `TABLE_ROW_H` per
    /// given row.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        let col = |c: &super::Col| match c.width {
            Width::Fixed(px) => s.px(px),
            Width::Share(_) => s.px(TABLE_COL_MIN),
        };
        let w = self.cols.iter().map(col).fold(0u32, u32::saturating_add);
        let n = u32::try_from(self.rows.len()).unwrap_or(u32::MAX);
        let rows = Self::row_h().saturating_mul(n);
        (w, Self::row_h().saturating_add(s.hair()).saturating_add(rows))
    }

    /// The body text size titles and cells are drawn at.
    pub(super) fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// How tall the header and each row are: `TABLE_ROW_H`.
    pub(super) fn row_h() -> u32 {
        scale().px(TABLE_ROW_H)
    }
}

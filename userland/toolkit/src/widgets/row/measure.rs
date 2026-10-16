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

//! A row's height and the stacked text it is measured from.

use super::Row;
use crate::design::scale::scale;
use crate::design::size::{LINE_GAP, ROW_H, ROW_NOTE_H};
use crate::design::text_role::TextRole;
use crate::font::ttf::line_height;

impl Row<'_> {
    /// No width of its own and the row height: `ROW_H`, or `ROW_NOTE_H` with
    /// a note, raised to the stacked text when that is taller. A row fills
    /// the width it is given.
    pub fn size(&self) -> (u32, u32) {
        let logical = if self.note.is_some() { ROW_NOTE_H } else { ROW_H };
        (0, scale().px(logical).max(self.block().1))
    }

    /// The body text size, the height of the stacked label and note, and one
    /// line.
    pub(super) fn block(&self) -> (f32, u32, u32) {
        let px = scale().font(TextRole::Body.px());
        let lh = line_height(px).max(0) as u32;
        let gap = scale().px(LINE_GAP);
        let block = if self.note.is_some() { lh.saturating_mul(2).saturating_add(gap) } else { lh };
        (px, block, lh)
    }
}

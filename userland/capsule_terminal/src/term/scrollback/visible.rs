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

use super::types::Scrollback;
use super::view::ScrollbackView;
use crate::term::dimensions::VISIBLE_ROWS;

impl Scrollback {
    pub fn visible(&self) -> ScrollbackView<'_> {
        let total_visible = self.count.min(VISIBLE_ROWS);
        let end_row_logical = self.count.saturating_sub(self.view_offset);
        let start_row_logical = end_row_logical.saturating_sub(total_visible);
        ScrollbackView { sb: self, start: start_row_logical, end: end_row_logical }
    }
}

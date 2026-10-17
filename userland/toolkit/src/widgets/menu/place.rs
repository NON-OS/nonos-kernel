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

//! Where a menu opens by its anchor, inside the bounds it may use.

use super::Menu;
use crate::decorations::Rect;
use crate::widgets::beside::beside;

impl Menu<'_> {
    /// The rect to draw the menu at, its size cut to `bounds`. It opens
    /// right under `anchor`, such as a menu title or the pointer, and flips
    /// above it when there is no room below but room above. When neither
    /// side fits it keeps as near below as `bounds` allows, over the anchor.
    /// Across, it starts at the anchor's left edge and shifts left, or right,
    /// to stay in `bounds`. All three rects are in drawing pixels. The app
    /// closes the menu when a press lands outside the rect this gives.
    pub fn place(&self, anchor: Rect, bounds: Rect) -> Rect {
        beside(anchor, bounds, self.size(), 0, true, |_| i64::from(anchor.x))
    }
}

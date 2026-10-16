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

//! The scrolled view and the screen span a content span maps to.

use crate::paint::PaintBuffer;

/// A `PaintBuffer` seen through a vertical scroll offset. Every y is a
/// content y; its screen y is that minus `scroll`.
pub struct Scrolled<'s, 'b> {
    pub(super) fb: &'s mut PaintBuffer<'b>,
    pub(super) scroll: u32,
}

impl<'s, 'b> Scrolled<'s, 'b> {
    /// Paints into `fb` with the content scrolled up by `scroll` pixels.
    pub fn new(fb: &'s mut PaintBuffer<'b>, scroll: u32) -> Self {
        Scrolled { fb, scroll }
    }

    /// The screen top and height of content rows `y` to `y + h` cut to the
    /// buffer, or None when none of them is on screen.
    pub(super) fn visible(&self, y: u32, h: u32) -> Option<(u32, u32)> {
        let top = i64::from(y) - i64::from(self.scroll);
        let bottom = (top + i64::from(h)).min(i64::from(self.fb.height));
        let top = top.max(0);
        (bottom > top).then(|| (top as u32, (bottom - top) as u32))
    }
}

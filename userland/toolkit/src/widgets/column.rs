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
//! A column that hands out rectangles down a box, in order, so a screen stops
//! adding up `y` by hand. It is not a layout engine: it measures nothing.

use crate::decorations::Rect;

/// What is left of a box, handed out from the top. Every step saturates, so a
/// column that runs out hands out empty rectangles at its bottom edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Column {
    left: Rect,
    gap: u32,
}

impl Column {
    /// A column over all of `at`, with no gap between what it hands out.
    pub fn new(at: Rect) -> Self {
        Column { left: at, gap: 0 }
    }

    /// The space left between one rectangle and the next, in drawing pixels.
    pub fn gap(mut self, gap: u32) -> Self {
        self.gap = gap;
        self
    }

    /// The next `h` of the column, as wide as the column and never taller
    /// than what is left; then the gap is passed over.
    pub fn next(&mut self, h: u32) -> Rect {
        let out = Rect { h: h.min(self.left.h), ..self.left };
        let used = out.h.saturating_add(self.gap).min(self.left.h);
        self.left =
            Rect { y: self.left.y.saturating_add(used), h: self.left.h - used, ..self.left };
        out
    }

    /// Everything not handed out yet.
    pub fn rest(&self) -> Rect {
        self.left
    }
}

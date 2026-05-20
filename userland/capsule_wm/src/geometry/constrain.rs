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

use super::rect::Rect;

pub const MIN_WINDOW_DIM: u32 = 16;

// Pushes `rect` inside the display bounding box. Clamps origin so
// the window stays on screen; clamps size so it cannot exceed the
// display and stays above MIN_WINDOW_DIM. Returns the constrained
// rect (never panics, never overflows).
pub fn clamp_to_display(rect: Rect, display_w: u32, display_h: u32) -> Rect {
    let max_w = core::cmp::max(display_w, MIN_WINDOW_DIM);
    let max_h = core::cmp::max(display_h, MIN_WINDOW_DIM);
    let width = rect.width.clamp(MIN_WINDOW_DIM, max_w);
    let height = rect.height.clamp(MIN_WINDOW_DIM, max_h);
    let max_x = max_w.saturating_sub(width);
    let max_y = max_h.saturating_sub(height);
    Rect { x: rect.x.min(max_x), y: rect.y.min(max_y), width, height }
}

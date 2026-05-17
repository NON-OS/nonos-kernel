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

use super::manifest::{HEIGHT, WIDTH};

pub const PADDING: u32 = 12;
pub const DISPLAY_H: u32 = 90;
pub const GRID_ROWS: u32 = 5;
pub const GRID_COLS: u32 = 4;
pub const GAP: u32 = 8;
pub const GRID_TOP: u32 = PADDING + DISPLAY_H + PADDING;

pub fn cell_size() -> (u32, u32) {
    let grid_w = WIDTH - PADDING * 2 - GAP * (GRID_COLS - 1);
    let grid_h = HEIGHT - GRID_TOP - PADDING - GAP * (GRID_ROWS - 1);
    (grid_w / GRID_COLS, grid_h / GRID_ROWS)
}

pub fn cell_origin(row: u32, col: u32, cell_w: u32, cell_h: u32) -> (u32, u32) {
    let x = PADDING + col * (cell_w + GAP);
    let y = GRID_TOP + row * (cell_h + GAP);
    (x, y)
}

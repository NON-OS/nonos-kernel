// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::*;
use super::utils::{draw_rounded_rect, draw_string};
use crate::display::framebuffer::{COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::graphics::framebuffer::{fill_rect};

pub(super) fn draw_header(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, HEADER_HEIGHT, COLOR_ROW_ALT);
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, COLOR_BORDER);
    draw_string(x + 16, y + 14, b"System Processes", COLOR_ACCENT);
    draw_rounded_rect(x + w - 90, y + 8, 76, 28, 6, 0xFF2A2A32);
    draw_string(x + w - 76, y + 14, b"Refresh", COLOR_TEXT_WHITE);
}

pub(super) fn draw_table_header(x: u32, y: u32, w: u32) {
    let ty = y + HEADER_HEIGHT;
    fill_rect(x, ty, w, TABLE_HEADER_HEIGHT, COLOR_HEADER);
    fill_rect(x, ty + TABLE_HEADER_HEIGHT - 1, w, 1, COLOR_BORDER);
    draw_string(x + 16, ty + 8, b"PID", COLOR_TEXT_DIM);
    draw_string(x + 60, ty + 8, b"Name", COLOR_TEXT_DIM);
    draw_string(x + 200, ty + 8, b"Status", COLOR_TEXT_DIM);
    draw_string(x + 290, ty + 8, b"Priority", COLOR_TEXT_DIM);
    draw_string(x + 370, ty + 8, b"Memory", COLOR_TEXT_DIM);
    draw_string(x + w - 70, ty + 8, b"Action", COLOR_TEXT_DIM);
}

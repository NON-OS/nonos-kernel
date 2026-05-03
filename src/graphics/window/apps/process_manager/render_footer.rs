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
use super::utils::{draw_number, draw_string};
use crate::display::framebuffer::{COLOR_ACCENT, COLOR_GREEN};
use crate::graphics::framebuffer::{fill_rect};

pub(super) fn draw_footer(x: u32, y: u32, w: u32, h: u32, count: u32, running: u32, mem: u64) {
    let fy = y + h - FOOTER_HEIGHT;
    fill_rect(x, fy, w, 1, COLOR_BORDER);
    fill_rect(x, fy + 1, w, FOOTER_HEIGHT - 1, 0xFF16161A);
    let ty = fy + 10;
    let w1 = draw_number(x + 16, ty, count, COLOR_TEXT_DIM);
    draw_string(x + 16 + w1, ty, b" processes", COLOR_TEXT_DIM);
    fill_rect(x + 16 + w1 + 88, ty - 4, 1, 12, COLOR_BORDER);
    let off2 = x + 16 + w1 + 96;
    let w2 = draw_number(off2, ty, running, COLOR_GREEN);
    draw_string(off2 + w2, ty, b" running", COLOR_TEXT_DIM);
    fill_rect(off2 + w2 + 72, ty - 4, 1, 12, COLOR_BORDER);
    let off3 = off2 + w2 + 80;
    let w3 = draw_number(off3, ty, mem as u32, COLOR_ACCENT);
    draw_string(off3 + w3, ty, b" KB", COLOR_TEXT_DIM);
}

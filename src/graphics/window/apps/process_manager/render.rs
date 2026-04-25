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
use super::render_footer::draw_footer;
use super::render_header::{draw_header, draw_table_header};
use super::render_rows::draw_row;
use crate::graphics::framebuffer::fill_rect;
use crate::process::get_all_processes;

pub(crate) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_header(x, y, w);
    draw_table_header(x, y, w);
    let processes = get_all_processes();
    let rows_start = y + HEADER_HEIGHT + TABLE_HEADER_HEIGHT + 4;
    let max_rows =
        ((h - HEADER_HEIGHT - TABLE_HEADER_HEIGHT - FOOTER_HEIGHT - 8) / ROW_HEIGHT) as usize;
    let mut total_mem: u64 = 0;
    let mut running_count = 0u32;
    for (i, proc) in processes.iter().take(max_rows).enumerate() {
        let (is_run, mem) = draw_row(x, rows_start, w, i, proc);
        if is_run {
            running_count += 1;
        }
        total_mem += mem;
    }
    draw_footer(x, y, w, h, processes.len() as u32, running_count, total_mem);
}

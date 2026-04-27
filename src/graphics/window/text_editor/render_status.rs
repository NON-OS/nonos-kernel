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

use super::cursor as cur;
use super::render_linenum::format_number;
use super::state::*;
use crate::graphics::components::text;
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub(super) fn draw_status_bar(x: u32, y: u32, w: u32, h: u32) {
    let bar_y = y + h - STATUS_BAR_HEIGHT;
    for gy in 0..STATUS_BAR_HEIGHT {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, bar_y + gy, w, 1, color);
    }
    fill_rect(x, bar_y, w, 1, BORDER_DEFAULT);
    let path_len = EDITOR_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        let display_len = path_len.min(30);
        unsafe {
            text::draw(x + 12, bar_y + 8, &EDITOR_FILE_PATH[..display_len], TEXT_SECONDARY);
        }
    } else {
        text::draw(x + 12, bar_y + 8, b"untitled", TEXT_SECONDARY);
    }
    draw_position(x, bar_y, w);
}

fn draw_position(x: u32, bar_y: u32, w: u32) {
    let (line, col) = cur::get_line_col();
    let mut pos_buf = [0u8; 20];
    let mut idx = 0;
    pos_buf[idx..idx + 3].copy_from_slice(b"Ln ");
    idx += 3;
    idx += format_number(&mut pos_buf[idx..], line);
    pos_buf[idx..idx + 5].copy_from_slice(b" Col ");
    idx += 5;
    idx += format_number(&mut pos_buf[idx..], col);
    text::draw(x + w - 130, bar_y + 8, &pos_buf[..idx], TEXT_SECONDARY);
}

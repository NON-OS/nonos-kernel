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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::design_system::colors::*;
use crate::graphics::components::{primitives, text};
use super::state::*;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, BG_APP);
    draw_header(x, y, w);
    draw_file_list(x, y, w, h);
    draw_buttons(x, y, w, h);
}

fn draw_header(x: u32, y: u32, w: u32) {
    for gy in 0..44u32 {
        let shade = 44 - (gy / 3) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + 43, w, 1, BORDER_DEFAULT);
    text::draw(x + 16, y + 14, b"Open File", TEXT_PRIMARY);

    let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        unsafe {
            let display_len = path_len.min(45);
            text::draw(x + 100, y + 14, &PICKER_PATH[..display_len], TEXT_SECONDARY);
        }
    }
}

fn draw_file_list(x: u32, y: u32, w: u32, h: u32) {
    let list_y = y + 48;
    let list_h = h - 100;
    let row_height = 28u32;

    fill_rect(x + 12, list_y, w - 24, list_h, BG_SURFACE);

    let count = PICKER_COUNT.load(Ordering::Relaxed);
    let selected = PICKER_SELECTED.load(Ordering::Relaxed);
    let max_rows = (list_h / row_height) as usize;

    for i in 0..count.min(max_rows) {
        let row_y = list_y + (i as u32) * row_height;
        if i == selected {
            primitives::rounded_rect(x + 16, row_y + 2, w - 32, row_height - 4, 4, BG_SELECTED);
        }

        let (name_len, is_dir) = unsafe { (PICKER_LENS[i], PICKER_IS_DIR[i]) };
        if name_len > 0 {
            let icon_color = if is_dir { ACCENT } else { TEXT_SECONDARY };
            if is_dir {
                fill_rect(x + 24, row_y + 7, 16, 12, icon_color);
            } else {
                fill_rect(x + 26, row_y + 5, 12, 16, icon_color);
            }
            unsafe { text::draw(x + 48, row_y + 8, &PICKER_FILES[i][..name_len], TEXT_PRIMARY); }
        }
    }
}

fn draw_buttons(x: u32, y: u32, w: u32, h: u32) {
    let btn_y = y + h - 48;
    primitives::rounded_rect(x + w - 90, btn_y, 72, 32, 6, BG_HOVER);
    text::draw(x + w - 76, btn_y + 10, b"Cancel", TEXT_PRIMARY);
    primitives::rounded_rect(x + w - 172, btn_y, 72, 32, 6, ACCENT);
    text::draw(x + w - 160, btn_y + 10, b"Open", TEXT_INVERSE);
}

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

use super::render_picker_list::draw_file_list;
use super::state::*;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, BG_APP);
    let is_save = picker_is_save_mode();
    draw_header(x, y, w, is_save);
    if is_save {
        draw_filename_input(x, y, w);
    }
    draw_file_list(x, y, w, h);
    draw_buttons(x, y, w, h, is_save);
}

fn draw_header(x: u32, y: u32, w: u32, is_save: bool) {
    for gy in 0..44u32 {
        let shade = 44 - (gy / 3) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + 43, w, 1, BORDER_DEFAULT);
    let title = if is_save { b"Save File As" as &[u8] } else { b"Open File" as &[u8] };
    text::draw(x + 16, y + 14, title, TEXT_PRIMARY);
    let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        unsafe {
            let display_len = path_len.min(40);
            text::draw(x + 120, y + 14, &PICKER_PATH[..display_len], TEXT_SECONDARY);
        }
    }
}

fn draw_filename_input(x: u32, y: u32, w: u32) {
    let input_y = y + 48;
    text::draw(x + 16, input_y + 4, b"Filename:", TEXT_SECONDARY);
    primitives::rounded_rect(x + 90, input_y, w - 110, 28, 4, BG_INPUT);
    let filename = get_save_filename();
    text::draw(x + 98, input_y + 8, filename, TEXT_PRIMARY);
    let cursor_x = x + 98 + (filename.len() as u32 * 8);
    fill_rect(cursor_x, input_y + 6, 2, 16, ACCENT);
}

fn draw_buttons(x: u32, y: u32, w: u32, h: u32, is_save: bool) {
    let btn_y = y + h - 48;
    primitives::rounded_rect(x + w - 90, btn_y, 72, 32, 6, BG_HOVER);
    text::draw(x + w - 76, btn_y + 10, b"Cancel", TEXT_PRIMARY);
    let action_text = if is_save { b"Save" as &[u8] } else { b"Open" as &[u8] };
    let action_x = if is_save { x + w - 160 } else { x + w - 160 };
    primitives::rounded_rect(x + w - 172, btn_y, 72, 32, 6, ACCENT);
    text::draw(action_x, btn_y + 10, action_text, TEXT_INVERSE);
}

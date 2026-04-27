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

use super::state::*;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub(super) fn draw_file_list(x: u32, y: u32, w: u32, h: u32) {
    let is_save = picker_is_save_mode();
    let list_y = y + if is_save { 84 } else { 48 };
    let list_h = h - if is_save { 136 } else { 100 };
    let row_height = 28u32;
    fill_rect(x + 12, list_y, w - 24, list_h, BG_SURFACE);
    let count = PICKER_COUNT.load(Ordering::Relaxed);
    let selected = PICKER_SELECTED.load(Ordering::Relaxed);
    let max_rows = (list_h / row_height) as usize;
    for i in 0..count.min(max_rows) {
        draw_file_row(x, list_y, w, i, row_height, selected);
    }
}

fn draw_file_row(x: u32, list_y: u32, w: u32, i: usize, row_height: u32, selected: usize) {
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
        unsafe {
            text::draw(x + 48, row_y + 8, &PICKER_FILES[i][..name_len], TEXT_PRIMARY);
        }
    }
}

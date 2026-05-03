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

use super::constants::ROW_HEIGHT;
use super::state::get_input_text;
use super::types::FileEntry;
use super::utils::format_size;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;

pub fn draw_rename_input(x: u32, ry: u32) {
    primitives::rounded_rect(x + 40, ry + 4, 200, ROW_HEIGHT - 8, 4, BG_INPUT);
    let input_text = get_input_text();
    text::draw(x + 48, ry + 10, input_text.as_bytes(), TEXT_PRIMARY);
    let cursor_x = x + 48 + (input_text.len() as u32) * 8;
    fill_rect(cursor_x, ry + 8, 2, 16, ACCENT);
}

pub fn draw_size_column(x: u32, ry: u32, w: u32, entry: &FileEntry) {
    if !entry.is_dir {
        let mut size_buf = [0u8; 10];
        format_size(entry.size, &mut size_buf);
        text::draw(x + w - 100, ry + 10, &size_buf, TEXT_SECONDARY);
    } else {
        text::draw(x + w - 100, ry + 10, b"Folder", TEXT_SECONDARY);
    }
}

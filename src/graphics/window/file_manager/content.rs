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

use super::constants::*;
use super::content_list;
use super::state::*;
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    draw_header(x, y, w);
    draw_list_header(x, y + HEADER_HEIGHT, w);
    draw_status_bar(x, y, w, h);
    content_list::draw(x, y, w, h);
}

fn draw_header(x: u32, y: u32, w: u32) {
    for gy in 0..HEADER_HEIGHT {
        let shade = 44 - (gy / 3) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, BORDER_DEFAULT);
    let path = get_path();
    text::draw(x + 16, y + 14, path.as_bytes(), TEXT_PRIMARY);
    if path != "/" && path != "/ram" && path != "/disk" {
        primitives::rounded_rect(x + w - 90, y + 8, 76, 28, 6, BG_HOVER);
        text::draw(x + w - 80, y + 14, b"<- Back", TEXT_PRIMARY);
    }
}

fn draw_list_header(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, LIST_HEADER_HEIGHT, BG_SURFACE);
    fill_rect(x, y + LIST_HEADER_HEIGHT - 1, w, 1, BORDER_DEFAULT);
    text::draw(x + 16, y + 8, b"Name", TEXT_SECONDARY);
    text::draw(x + w - 100, y + 8, b"Size", TEXT_SECONDARY);
}

fn draw_status_bar(x: u32, y: u32, w: u32, h: u32) {
    for gy in 0..STATUS_BAR_HEIGHT {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + h - STATUS_BAR_HEIGHT + gy, w, 1, color);
    }
    fill_rect(x, y + h - STATUS_BAR_HEIGHT, w, 1, BORDER_DEFAULT);
    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);
    let mut status_buf = [b' '; 16];
    status_buf[0] = b'0' + (count / 10);
    status_buf[1] = b'0' + (count % 10);
    status_buf[2..9].copy_from_slice(b" items ");
    text::draw(x + 16, y + h - 20, &status_buf[..9], TEXT_SECONDARY);
}

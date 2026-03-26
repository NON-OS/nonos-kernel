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
use crate::graphics::font::draw_char;
use crate::graphics::design_system::colors::*;
use crate::graphics::components::{primitives, text};
use super::constants::SIDEBAR_WIDTH;
use super::state::{get_path, FM_SELECTED_ITEM};
use super::clipboard::has_clipboard;

pub fn draw(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, BG_SURFACE);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, BORDER_DEFAULT);
    text::draw(x + 12, y + 12, b"Locations", TEXT_SECONDARY);
    draw_locations(x, y);
    draw_actions(x, y + 190);
}

fn draw_locations(x: u32, y: u32) {
    let locations: [(&[u8], &[u8], u32); 4] = [
        (b"RAM Files", b"/ram", SUCCESS),
        (b"Disk 0", b"/disk/0", WARNING),
        (b"Disk 1", b"/disk/1", WARNING),
        (b"Root", b"/", ACCENT),
    ];
    let path = get_path();

    for (i, (label, loc_path, icon_color)) in locations.iter().enumerate() {
        let iy = y + 36 + (i as u32) * 36;
        let is_sel = path.starts_with(unsafe { core::str::from_utf8_unchecked(loc_path) });
        if is_sel {
            primitives::rounded_rect(x + 8, iy, SIDEBAR_WIDTH - 16, 32, 6, BG_HOVER);
        }
        fill_rect(x + 16, iy + 8, 20, 16, *icon_color);
        draw_char(x + 20, iy + 10, 0x1A, TEXT_INVERSE);
        let text_color = if is_sel { TEXT_PRIMARY } else { TEXT_SECONDARY };
        text::draw(x + 44, iy + 10, label, text_color);
    }
}

fn draw_actions(x: u32, y: u32) {
    text::draw(x + 12, y, b"Actions", TEXT_SECONDARY);
    let ops: [(&[u8], u32); 7] = [
        (b"New Folder", SUCCESS),
        (b"New File", ACCENT),
        (b"Copy", 0xFF5856D6),
        (b"Cut", WARNING),
        (b"Paste", SUCCESS),
        (b"Delete", ERROR),
        (b"Rename", TEXT_SECONDARY),
    ];
    let has_sel = FM_SELECTED_ITEM.load(Ordering::Relaxed) != 255;
    let has_clip = has_clipboard();

    for (i, (label, btn_color)) in ops.iter().enumerate() {
        let oy = y + 24 + (i as u32) * 26;
        let enabled = match i {
            0 | 1 => true,
            2 | 3 | 5 | 6 => has_sel,
            4 => has_clip,
            _ => true,
        };
        let bg = if enabled { BG_ELEVATED } else { BG_DISABLED };
        primitives::rounded_rect(x + 8, oy, SIDEBAR_WIDTH - 16, 22, 4, bg);
        if enabled { fill_rect(x + 14, oy + 4, 14, 14, *btn_color); }
        let text_color = if enabled { TEXT_SECONDARY } else { TEXT_DISABLED };
        text::draw(x + 34, oy + 5, label, text_color);
    }
}

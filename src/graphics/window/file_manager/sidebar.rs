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
use super::state::get_path;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE};

fn draw_text(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r {
        for dx in 0..r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(x + r - dx, y + r - dy, color);
                put_pixel(x + w - r + dx - 1, y + r - dy, color);
                put_pixel(x + r - dx, y + h - r + dy - 1, color);
                put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
            }
        }
    }
}

fn draw_folder_icon(x: u32, y: u32, color: u32) {
    fill_rect(x, y + 3, 18, 14, color);
    fill_rect(x, y, 8, 4, color);
}

pub fn draw(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, COLOR_SIDEBAR_BG);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, 0xFF2C2C30);
    draw_text(x + 12, y + 12, b"Favourites", COLOR_TEXT_DIM);
    let favs: [(&[u8], &[u8], u32); 5] = [
        (b"Recents", b"/ram/recents", COLOR_ICON_RECENTS),
        (b"Applications", b"/ram/apps", COLOR_ICON_APPS),
        (b"Downloads", b"/ram/downloads", COLOR_ICON_DOWNLOADS),
        (b"Desktop", b"/ram/desktop", COLOR_ICON_DESKTOP),
        (b"Documents", b"/ram/docs", COLOR_ICON_DOCS),
    ];
    let path = get_path();
    for (i, (label, fp, ic)) in favs.iter().enumerate() {
        let iy = y + 36 + (i as u32) * 28;
        let sel = path.starts_with(unsafe { core::str::from_utf8_unchecked(fp) });
        if sel {
            draw_rounded_rect(x + 8, iy - 2, SIDEBAR_WIDTH - 16, 24, 4, COLOR_SIDEBAR_SELECTED);
        }
        draw_folder_icon(x + 16, iy + 2, *ic);
        let tc = if sel { COLOR_TEXT_WHITE } else { COLOR_TEXT_LIGHT };
        draw_text(x + 40, iy + 4, label, tc);
    }
}

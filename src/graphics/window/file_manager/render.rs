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
use super::state::{get_input_text, get_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_CREATING_FILE,
    FM_CREATING_FOLDER, FM_RENAMING, FM_SELECTED_ITEM};
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE};
use core::sync::atomic::Ordering;

fn draw_text(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() { draw_char(x + (i as u32) * 8, y, ch, color); }
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

fn draw_folder_large(x: u32, y: u32, color: u32) {
    fill_rect(x, y + 8, 48, 32, color);
    fill_rect(x, y, 20, 10, color);
    fill_rect(x + 20, y + 4, 4, 6, color);
    fill_rect(x + 2, y + 12, 44, 2, 0x20FFFFFF);
}

fn draw_file_icon(x: u32, y: u32, color: u32) {
    fill_rect(x + 2, y, 12, 18, color);
    fill_rect(x + 2, y, 8, 4, 0xFF48484A);
    fill_rect(x + 10, y + 4, 4, 4, 0xFF48484A);
}

pub fn draw_file_manager(x: u32, y: u32, w: u32, h: u32) {
    let sw = SIDEBAR_WIDTH.min(w.saturating_sub(100));
    if sw > 60 { draw_sidebar(x, y, h, sw); }
    let cx = x + sw;
    let cw = w.saturating_sub(sw);
    if cw > 100 { draw_content(cx, y, cw, h); }
}

fn draw_sidebar(x: u32, y: u32, h: u32, sw: u32) {
    fill_rect(x, y, sw, h, COLOR_SIDEBAR_BG);
    fill_rect(x + sw - 1, y, 1, h, 0xFF2C2C30);
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
        if sel { draw_rounded_rect(x + 8, iy - 2, sw - 16, 24, 4, COLOR_SIDEBAR_SELECTED); }
        draw_folder_icon(x + 16, iy + 2, *ic);
        let tc = if sel { COLOR_TEXT_WHITE } else { COLOR_TEXT_LIGHT };
        draw_text(x + 40, iy + 4, label, tc);
    }
}

fn draw_content(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, HEADER_HEIGHT, 0xFF1E1E24);
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, 0xFF2C2C30);
    let path = get_path();
    let title = path.rsplit('/').next().unwrap_or("Documents");
    draw_text(x + 50, y + 16, title.as_bytes(), COLOR_TEXT_WHITE);
    draw_rounded_rect(x + 12, y + 12, 14, 20, 3, 0xFF3A3A40);
    draw_text(x + 15, y + 16, b"<", COLOR_TEXT_LIGHT);
    draw_rounded_rect(x + 30, y + 12, 14, 20, 3, 0xFF3A3A40);
    draw_text(x + 33, y + 16, b">", COLOR_TEXT_LIGHT);
    let col_x = x + w - 120;
    draw_text(col_x, y + 16, path.rsplit('/').next().unwrap_or("Documents").as_bytes(), COLOR_TEXT_DIM);
    fill_rect(col_x + 80, y + 18, 12, 12, 0xFF3A3A40);
    draw_text(col_x + 82, y + 18, b"+", COLOR_TEXT_LIGHT);
    let list_y = y + HEADER_HEIGHT;
    let list_h = h - HEADER_HEIGHT - STATUS_BAR_HEIGHT;
    fill_rect(x, list_y, w, list_h, 0xFF000000);
    draw_file_grid(x, list_y, w, list_h);
    fill_rect(x, y + h - STATUS_BAR_HEIGHT, w, 1, 0xFF2C2C30);
    fill_rect(x, y + h - STATUS_BAR_HEIGHT + 1, w, STATUS_BAR_HEIGHT - 1, 0xFF16161A);
    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);
    let sel = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    let sel_count = if sel < count { 1 } else { 0 };
    let mut buf = [0u8; 32];
    let len = format_status(&mut buf, sel_count, count);
    draw_text(x + 16, y + h - 20, &buf[..len], COLOR_TEXT_DIM);
}

fn draw_file_grid(x: u32, y: u32, w: u32, _h: u32) {
    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    let creating_folder = FM_CREATING_FOLDER.load(Ordering::Relaxed);
    let creating_file = FM_CREATING_FILE.load(Ordering::Relaxed);
    let cols = (w / 100).max(1);
    let mut idx = 0u8;
    if creating_folder || creating_file {
        let cx = x + 20 + (idx as u32 % cols) * 100;
        let cy = y + 16 + (idx as u32 / cols) * 100;
        draw_folder_large(cx, cy, COLOR_FOLDER);
        draw_rounded_rect(cx - 4, cy + 48, 56, 18, 4, 0xFF1A1A1E);
        let input = get_input_text();
        draw_text(cx, cy + 50, input.as_bytes(), COLOR_TEXT_WHITE);
        idx += 1;
    }
    for i in 0..count.min(24) {
        let entry = unsafe { &FILE_ENTRIES[i as usize] };
        let cx = x + 20 + ((idx + i) as u32 % cols) * 100;
        let cy = y + 16 + ((idx + i) as u32 / cols) * 100;
        if i == selected {
            draw_rounded_rect(cx - 8, cy - 8, 64, 80, 8, COLOR_ROW_SELECTED);
        }
        if entry.is_dir {
            draw_folder_large(cx, cy, COLOR_FOLDER);
        } else {
            fill_rect(cx + 8, cy, 32, 40, COLOR_FILE);
        }
        if i == selected && FM_RENAMING.load(Ordering::Relaxed) {
            draw_rounded_rect(cx - 4, cy + 48, 56, 18, 4, 0xFF1A1A1E);
            let input = get_input_text();
            draw_text(cx, cy + 50, input.as_bytes(), COLOR_TEXT_WHITE);
        } else {
            let name_len = entry.name_len.min(7) as usize;
            draw_text(cx, cy + 50, &entry.name[..name_len], COLOR_TEXT_WHITE);
        }
    }
}

fn format_status(buf: &mut [u8; 32], sel: u8, total: u8) -> usize {
    let mut i = 0;
    buf[i] = b'0' + sel; i += 1;
    buf[i..i+4].copy_from_slice(b" of "); i += 4;
    buf[i] = b'0' + total; i += 1;
    buf[i..i+10].copy_from_slice(b" selected,"); i += 10;
    buf[i..i+14].copy_from_slice(b" 42.05 GB free"); i += 14;
    i
}

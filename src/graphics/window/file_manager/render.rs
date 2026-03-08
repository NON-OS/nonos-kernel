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
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use super::constants::*;
use super::state::{get_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM, FM_RENAMING, FM_CREATING_FOLDER, FM_CREATING_FILE, get_input_text};
use super::clipboard::has_clipboard;

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
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

fn draw_file_icon(x: u32, y: u32, color: u32) {
    fill_rect(x + 2, y, 12, 18, color);
    fill_rect(x + 2, y, 8, 4, 0xFF48484A);
    fill_rect(x + 10, y + 4, 4, 4, 0xFF48484A);
}

pub fn draw_file_manager(x: u32, y: u32, w: u32, h: u32) {
    draw_sidebar(x, y, h);

    let content_x = x + SIDEBAR_WIDTH;
    let content_w = w - SIDEBAR_WIDTH;
    draw_content_area(content_x, y, content_w, h);
}

fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, COLOR_SIDEBAR_BG);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, 0xFF38383A);

    draw_string(x + 12, y + 12, b"Locations", COLOR_TEXT_DIM);

    let locations: [(&[u8], &[u8], u32); 4] = [
        (b"RAM Files", b"/ram", COLOR_ICON_RAM),
        (b"Disk 0", b"/disk/0", COLOR_ICON_DISK),
        (b"Disk 1", b"/disk/1", COLOR_ICON_DISK),
        (b"Root", b"/", COLOR_ICON_ROOT),
    ];

    let path = get_path();

    for (i, (label, loc_path, icon_color)) in locations.iter().enumerate() {
        let iy = y + 36 + (i as u32) * 36;
        let is_selected = path.starts_with(unsafe { core::str::from_utf8_unchecked(loc_path) });

        if is_selected {
            draw_rounded_rect(x + 8, iy, SIDEBAR_WIDTH - 16, 32, 6, COLOR_SIDEBAR_SELECTED);
        }

        fill_rect(x + 16, iy + 8, 20, 16, *icon_color);
        draw_char(x + 20, iy + 10, 0x1A, 0xFFFFFFFF);

        let text_color = if is_selected { COLOR_TEXT_WHITE } else { COLOR_TEXT_LIGHT };
        draw_string(x + 44, iy + 10, label, text_color);
    }

    let ops_y = y + 190;
    draw_string(x + 12, ops_y, b"Actions", COLOR_TEXT_DIM);

    let ops: [(&[u8], u32); 7] = [
        (b"New Folder", 0xFF34C759),
        (b"New File", 0xFF007AFF),
        (b"Copy", 0xFF5856D6),
        (b"Cut", 0xFFFF9500),
        (b"Paste", 0xFF34C759),
        (b"Delete", 0xFFFF3B30),
        (b"Rename", 0xFF8E8E93),
    ];
    let has_selection = FM_SELECTED_ITEM.load(Ordering::Relaxed) != 255;
    let has_clip = has_clipboard();

    for (i, (label, btn_color)) in ops.iter().enumerate() {
        let oy = ops_y + 24 + (i as u32) * 26;
        let enabled = match i {
            0 | 1 => true,
            2 | 3 | 5 | 6 => has_selection,
            4 => has_clip,
            _ => true,
        };

        let bg = if enabled { COLOR_SIDEBAR_HEADER } else { 0xFF1A1A1C };
        draw_rounded_rect(x + 8, oy, SIDEBAR_WIDTH - 16, 22, 4, bg);

        if enabled {
            fill_rect(x + 14, oy + 4, 14, 14, *btn_color);
        }

        let text_color = if enabled { COLOR_TEXT_LIGHT } else { 0xFF48484A };
        draw_string(x + 34, oy + 5, label, text_color);
    }
}

fn draw_content_area(x: u32, y: u32, w: u32, h: u32) {
    for gy in 0..HEADER_HEIGHT {
        let shade = 44 - (gy / 3) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, 0xFF38383A);

    let path = get_path();
    draw_string(x + 16, y + 14, path.as_bytes(), COLOR_TEXT_WHITE);

    if path != "/" && path != "/ram" && path != "/disk" {
        draw_rounded_rect(x + w - 90, y + 8, 76, 28, 6, 0xFF3A3A3C);
        draw_string(x + w - 80, y + 14, b"<- Back", COLOR_TEXT_WHITE);
    }

    let list_header_y = y + HEADER_HEIGHT;
    fill_rect(x, list_header_y, w, LIST_HEADER_HEIGHT, COLOR_LIST_HEADER);
    fill_rect(x, list_header_y + LIST_HEADER_HEIGHT - 1, w, 1, 0xFF38383A);
    draw_string(x + 16, list_header_y + 8, b"Name", COLOR_TEXT_DIM);
    draw_string(x + w - 100, list_header_y + 8, b"Size", COLOR_TEXT_DIM);

    for gy in 0..STATUS_BAR_HEIGHT {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + h - STATUS_BAR_HEIGHT + gy, w, 1, color);
    }
    fill_rect(x, y + h - STATUS_BAR_HEIGHT, w, 1, 0xFF38383A);

    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);
    let mut status_buf = [b' '; 16];
    status_buf[0] = b'0' + (count / 10);
    status_buf[1] = b'0' + (count % 10);
    status_buf[2..9].copy_from_slice(b" items ");
    draw_string(x + 16, y + h - 20, &status_buf[..9], COLOR_TEXT_DIM);

    let list_y = y + HEADER_HEIGHT + LIST_HEADER_HEIGHT;
    let list_h = h - HEADER_HEIGHT - LIST_HEADER_HEIGHT - STATUS_BAR_HEIGHT;
    fill_rect(x, list_y, w, list_h, 0xFF000000);
    let max_rows = (list_h / ROW_HEIGHT) as u8;
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);

    let creating_folder = FM_CREATING_FOLDER.load(Ordering::Relaxed);
    let creating_file = FM_CREATING_FILE.load(Ordering::Relaxed);
    let creating = creating_folder || creating_file;

    if creating {
        let ry = list_y;
        draw_rounded_rect(x + 4, ry + 2, w - 8, ROW_HEIGHT - 4, 4, 0xFF1A3050);

        if creating_folder {
            draw_folder_icon(x + 12, ry + 6, COLOR_FOLDER);
        } else {
            draw_file_icon(x + 12, ry + 5, COLOR_FILE);
        }

        draw_rounded_rect(x + 40, ry + 4, 200, ROW_HEIGHT - 8, 4, 0xFF1C1C1E);

        let input_text = get_input_text();
        draw_string(x + 48, ry + 10, input_text.as_bytes(), COLOR_TEXT_WHITE);

        let cursor_x = x + 48 + (input_text.len() as u32) * 8;
        fill_rect(cursor_x, ry + 8, 2, 16, 0xFF007AFF);
    }

    let offset = if creating { 1 } else { 0 };

    for i in 0..count.min(max_rows.saturating_sub(offset)) {
        let entry = unsafe { &FILE_ENTRIES[i as usize] };
        let ry = list_y + ((i + offset) as u32) * ROW_HEIGHT;

        if i == selected {
            draw_rounded_rect(x + 4, ry + 2, w - 8, ROW_HEIGHT - 4, 4, COLOR_ROW_SELECTED);
        } else if i % 2 == 1 {
            fill_rect(x, ry, w, ROW_HEIGHT, COLOR_ROW_ALT);
        }

        if entry.is_dir {
            draw_folder_icon(x + 12, ry + 6, COLOR_FOLDER);
        } else {
            draw_file_icon(x + 12, ry + 5, COLOR_FILE);
        }

        if i == selected && FM_RENAMING.load(Ordering::Relaxed) {
            draw_rounded_rect(x + 40, ry + 4, 200, ROW_HEIGHT - 8, 4, 0xFF1C1C1E);

            let input_text = get_input_text();
            draw_string(x + 48, ry + 10, input_text.as_bytes(), COLOR_TEXT_WHITE);

            let cursor_x = x + 48 + (input_text.len() as u32) * 8;
            fill_rect(cursor_x, ry + 8, 2, 16, 0xFF007AFF);
        } else {
            draw_string(x + 40, ry + 10, &entry.name[..entry.name_len as usize], COLOR_TEXT_WHITE);
        }

        if !entry.is_dir {
            let mut size_buf = [0u8; 10];
            format_size(entry.size, &mut size_buf);
            draw_string(x + w - 100, ry + 10, &size_buf, COLOR_TEXT_DIM);
        } else {
            draw_string(x + w - 100, ry + 10, b"Folder", COLOR_TEXT_DIM);
        }
    }
}

fn format_size(size: u32, buf: &mut [u8; 10]) {
    buf.fill(0);
    if size < 1024 {
        let mut n = size;
        if n == 0 {
            buf[0..3].copy_from_slice(b"0 B");
            return;
        }
        let mut digits = [0u8; 5];
        let mut i = 0;
        while n > 0 {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        let mut j = 0;
        while i > 0 {
            i -= 1;
            buf[j] = digits[i];
            j += 1;
        }
        buf[j] = b' ';
        buf[j + 1] = b'B';
    } else if size < 1024 * 1024 {
        let kb = size / 1024;
        if kb >= 100 {
            buf[0] = b'0' + (kb / 100) as u8;
            buf[1] = b'0' + ((kb / 10) % 10) as u8;
            buf[2] = b'0' + (kb % 10) as u8;
            buf[3..6].copy_from_slice(b" KB");
        } else {
            buf[0] = b'0' + (kb / 10) as u8;
            buf[1] = b'0' + (kb % 10) as u8;
            buf[2..5].copy_from_slice(b" KB");
        }
    } else {
        let mb = size / (1024 * 1024);
        buf[0] = b'0' + (mb / 10) as u8;
        buf[1] = b'0' + (mb % 10) as u8;
        buf[2..5].copy_from_slice(b" MB");
    }
}

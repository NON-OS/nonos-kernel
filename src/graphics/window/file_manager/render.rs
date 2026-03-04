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
use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use super::constants::*;
use super::state::{get_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM};
use super::clipboard::has_clipboard;

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub fn draw_file_manager(x: u32, y: u32, w: u32, h: u32) {
    draw_sidebar(x, y, h);

    let content_x = x + SIDEBAR_WIDTH;
    let content_w = w - SIDEBAR_WIDTH;
    draw_content_area(content_x, y, content_w, h);
}

fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, COLOR_SIDEBAR_BG);

    fill_rect(x, y, SIDEBAR_WIDTH, 30, COLOR_SIDEBAR_HEADER);
    draw_string(x + 10, y + 8, b"Locations", COLOR_TEXT_DIM);

    let locations: [(&[u8], &[u8]); 4] = [
        (b"RAM Files", b"/ram"),
        (b"Disk 0", b"/disk/0"),
        (b"Disk 1", b"/disk/1"),
        (b"Root", b"/"),
    ];

    let path = get_path();

    for (i, (label, loc_path)) in locations.iter().enumerate() {
        let iy = y + 40 + (i as u32) * 32;
        let is_selected = path.starts_with(unsafe { core::str::from_utf8_unchecked(loc_path) });

        if is_selected {
            fill_rect(x, iy, SIDEBAR_WIDTH, 30, COLOR_SIDEBAR_SELECTED);
        }

        fill_rect(x + 10, iy + 7, 16, 12, if is_selected { COLOR_FOLDER } else { COLOR_TEXT_DIM });

        draw_string(x + 32, iy + 8, label, if is_selected { COLOR_TEXT_WHITE } else { COLOR_TEXT_LIGHT });
    }

    let ops_y = y + 180;
    fill_rect(x, ops_y, SIDEBAR_WIDTH, 25, COLOR_SIDEBAR_HEADER);
    draw_string(x + 10, ops_y + 6, b"Operations", COLOR_TEXT_DIM);

    let ops: [&[u8]; 6] = [b"New Folder", b"Copy", b"Cut", b"Paste", b"Delete", b"Rename"];
    let has_selection = FM_SELECTED_ITEM.load(Ordering::Relaxed) != 255;
    let has_clip = has_clipboard();

    for (i, label) in ops.iter().enumerate() {
        let oy = ops_y + 30 + (i as u32) * 24;
        let enabled = match i {
            0 => true,
            1 | 2 | 4 | 5 => has_selection,
            3 => has_clip,
            _ => true,
        };
        let btn_color = if enabled { COLOR_SIDEBAR_HEADER } else { 0xFF12161B };
        let text_color = if enabled { COLOR_TEXT_LIGHT } else { COLOR_TEXT_DIM };
        fill_rect(x + 5, oy, SIDEBAR_WIDTH - 10, 20, btn_color);
        draw_string(x + 15, oy + 4, label, text_color);
    }
}

fn draw_content_area(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, HEADER_HEIGHT, COLOR_PATH_BAR);
    let path = get_path();
    draw_string(x + 10, y + 10, path.as_bytes(), COLOR_TEXT_WHITE);

    if path != "/" && path != "/ram" && path != "/disk" {
        fill_rect(x + w - 80, y + 5, 70, 25, COLOR_SIDEBAR_HEADER);
        draw_string(x + w - 70, y + 10, b"<- Back", COLOR_TEXT_WHITE);
    }

    let list_header_y = y + HEADER_HEIGHT;
    fill_rect(x, list_header_y, w, LIST_HEADER_HEIGHT, COLOR_LIST_HEADER);
    draw_string(x + 10, list_header_y + 6, b"Name", COLOR_TEXT_DIM);
    draw_string(x + w - 100, list_header_y + 6, b"Size", COLOR_TEXT_DIM);

    fill_rect(x, y + h - STATUS_BAR_HEIGHT, w, STATUS_BAR_HEIGHT, COLOR_PATH_BAR);
    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);
    let mut status_buf = [b' '; 16];
    status_buf[0] = b'0' + (count / 10);
    status_buf[1] = b'0' + (count % 10);
    status_buf[2..9].copy_from_slice(b" items ");
    draw_string(x + 10, y + h - 18, &status_buf[..9], COLOR_TEXT_DIM);

    let list_y = y + HEADER_HEIGHT + LIST_HEADER_HEIGHT;
    let list_h = h - HEADER_HEIGHT - LIST_HEADER_HEIGHT - STATUS_BAR_HEIGHT;
    let max_rows = (list_h / ROW_HEIGHT) as u8;
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);

    for i in 0..count.min(max_rows) {
        // SAFETY: bounds checked
        let entry = unsafe { &FILE_ENTRIES[i as usize] };
        let ry = list_y + (i as u32) * ROW_HEIGHT;

        if i == selected {
            fill_rect(x, ry, w, ROW_HEIGHT, COLOR_ROW_SELECTED);
        } else if i % 2 == 1 {
            fill_rect(x, ry, w, ROW_HEIGHT, COLOR_ROW_ALT);
        }

        let icon_color = if entry.is_dir { COLOR_FOLDER } else { COLOR_FILE };
        if entry.is_dir {
            fill_rect(x + 10, ry + 8, 16, 12, icon_color);
        } else {
            fill_rect(x + 10, ry + 6, 14, 16, icon_color);
        }

        draw_string(x + 35, ry + 7, &entry.name[..entry.name_len as usize], COLOR_TEXT_WHITE);

        if !entry.is_dir {
            let mut size_buf = [0u8; 10];
            format_size(entry.size, &mut size_buf);
            draw_string(x + w - 100, ry + 7, &size_buf, COLOR_TEXT_DIM);
        } else {
            draw_string(x + w - 100, ry + 7, b"<DIR>", COLOR_TEXT_DIM);
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

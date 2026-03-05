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
use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE, COLOR_YELLOW, COLOR_GREEN, COLOR_RED, COLOR_ACCENT};
use crate::graphics::font::draw_char;
use super::state::*;
use super::file::is_modified;

pub(super) fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub(super) fn draw_file_picker(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, 0xFF0D1117);

    fill_rect(x, y, w, 35, 0xFF21262D);
    draw_string(x + 10, y + 10, b"Open File", COLOR_TEXT_WHITE);

    let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        // SAFETY: Single-threaded access during render
        unsafe {
            let display_len = path_len.min(50);
            draw_string(x + 100, y + 10, &PICKER_PATH[..display_len], 0xFF7D8590);
        }
    }

    let list_y = y + 40;
    let list_h = h - 85;
    let row_height = 24u32;

    fill_rect(x + 10, list_y, w - 20, list_h, 0xFF161B22);

    let count = PICKER_COUNT.load(Ordering::Relaxed);
    let selected = PICKER_SELECTED.load(Ordering::Relaxed);
    let max_rows = (list_h / row_height) as usize;

    for i in 0..count.min(max_rows) {
        let row_y = list_y + (i as u32) * row_height;

        if i == selected {
            fill_rect(x + 10, row_y, w - 20, row_height, 0xFF2D4A3A);
        }

        // SAFETY: Single-threaded access during render
        let (name_len, is_dir) = unsafe {
            (PICKER_LENS[i], PICKER_IS_DIR[i])
        };

        if name_len > 0 {
            let icon_color = if is_dir { COLOR_ACCENT } else { 0xFF7D8590 };
            if is_dir {
                fill_rect(x + 20, row_y + 6, 14, 10, icon_color);
            } else {
                fill_rect(x + 20, row_y + 4, 12, 14, icon_color);
            }

            // SAFETY: Single-threaded access during render
            unsafe {
                draw_string(x + 42, row_y + 5, &PICKER_FILES[i][..name_len], COLOR_TEXT_WHITE);
            }
        }
    }

    let btn_y = y + h - 40;

    fill_rect(x + w - 80, btn_y, 60, 25, 0xFF4A5568);
    draw_string(x + w - 68, btn_y + 6, b"Cancel", COLOR_TEXT_WHITE);

    fill_rect(x + w - 150, btn_y, 60, 25, COLOR_ACCENT);
    draw_string(x + w - 142, btn_y + 6, b"Open", 0xFF0D1117);
}

pub(super) fn draw_toolbar(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, TOOLBAR_HEIGHT, 0xFF21262D);

    let tools: [(&[u8], u32); 4] = [
        (b"New", 40),
        (b"Open", 48),
        (b"Save", 48),
        (b"Close", 56),
    ];

    let mut tx = x + 10;
    for (tool, btn_w) in tools.iter() {
        fill_rect(tx, y + 5, *btn_w, 25, 0xFF2D333B);
        draw_string(tx + 8, y + 10, tool, COLOR_TEXT_WHITE);
        tx += btn_w + 8;
    }

    let status = EDITOR_STATUS.load(Ordering::Relaxed);
    let modified = is_modified();

    let status_x = x + w - 100;
    match status {
        STATUS_SAVED => draw_string(status_x, y + 10, b"Saved", COLOR_GREEN),
        STATUS_OPENED => draw_string(status_x, y + 10, b"Opened", COLOR_ACCENT),
        STATUS_ERROR => draw_string(status_x, y + 10, b"Error", COLOR_RED),
        STATUS_NEW => draw_string(status_x, y + 10, b"New", COLOR_ACCENT),
        _ => {
            if modified {
                draw_string(status_x, y + 10, b"Modified", COLOR_YELLOW);
            }
        }
    }
}

pub(super) fn draw_line_numbers(x: u32, y: u32, h: u32) {
    fill_rect(x, y, LINE_NUM_WIDTH, h, 0xFF161B22);
}

pub(super) fn draw_line_number(x: u32, y: u32, num: usize) {
    let mut buf = [b' '; 4];
    let mut n = num;
    let mut i = 3;

    while n > 0 && i > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i -= 1;
    }

    for (j, &ch) in buf.iter().enumerate() {
        if ch != b' ' {
            draw_char(x + 5 + (j as u32) * 8, y, ch, 0xFF7D8590);
        }
    }
}

pub(super) fn draw_status_bar(x: u32, y: u32, w: u32, h: u32) {
    use super::cursor as cur;

    let bar_y = y + h - STATUS_BAR_HEIGHT;
    fill_rect(x, bar_y, w, STATUS_BAR_HEIGHT, 0xFF21262D);

    let path_len = EDITOR_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        let display_len = path_len.min(30);
        // SAFETY: Single-threaded access during render
        unsafe {
            draw_string(x + 10, bar_y + 7, &EDITOR_FILE_PATH[..display_len], 0xFF7D8590);
        }
    } else {
        draw_string(x + 10, bar_y + 7, b"untitled", 0xFF7D8590);
    }

    let (line, col) = cur::get_line_col();
    let mut pos_buf = [0u8; 20];
    let mut idx = 0;

    pos_buf[idx..idx + 3].copy_from_slice(b"Ln ");
    idx += 3;
    idx += format_number(&mut pos_buf[idx..], line);
    pos_buf[idx..idx + 5].copy_from_slice(b" Col ");
    idx += 5;
    idx += format_number(&mut pos_buf[idx..], col);

    draw_string(x + w - 120, bar_y + 7, &pos_buf[..idx], 0xFF7D8590);
}

pub(super) fn format_number(buf: &mut [u8], num: usize) -> usize {
    if num == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut n = num;
    let mut digits = [0u8; 10];
    let mut count = 0;

    while n > 0 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }

    for i in 0..count {
        buf[i] = digits[count - 1 - i];
    }
    count
}

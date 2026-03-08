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
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE, COLOR_YELLOW, COLOR_GREEN, COLOR_RED, COLOR_ACCENT};
use crate::graphics::font::draw_char;
use super::state::*;
use super::file::is_modified;

const COLOR_BORDER: u32 = 0xFF38383A;
const COLOR_TEXT_DIM: u32 = 0xFF8E8E93;
const COLOR_BTN: u32 = 0xFF3A3A3C;

pub(super) fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
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

pub(super) fn draw_file_picker(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, 0xFF000000);

    for gy in 0..44u32 {
        let shade = 44 - (gy / 3) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + 43, w, 1, COLOR_BORDER);
    draw_string(x + 16, y + 14, b"Open File", COLOR_TEXT_WHITE);

    let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        unsafe {
            let display_len = path_len.min(45);
            draw_string(x + 100, y + 14, &PICKER_PATH[..display_len], COLOR_TEXT_DIM);
        }
    }

    let list_y = y + 48;
    let list_h = h - 100;
    let row_height = 28u32;

    fill_rect(x + 12, list_y, w - 24, list_h, 0xFF1C1C1E);

    let count = PICKER_COUNT.load(Ordering::Relaxed);
    let selected = PICKER_SELECTED.load(Ordering::Relaxed);
    let max_rows = (list_h / row_height) as usize;

    for i in 0..count.min(max_rows) {
        let row_y = list_y + (i as u32) * row_height;

        if i == selected {
            draw_rounded_rect(x + 16, row_y + 2, w - 32, row_height - 4, 4, 0xFF0A4A7A);
        }

        let (name_len, is_dir) = unsafe {
            (PICKER_LENS[i], PICKER_IS_DIR[i])
        };

        if name_len > 0 {
            let icon_color = if is_dir { COLOR_ACCENT } else { COLOR_TEXT_DIM };
            if is_dir {
                fill_rect(x + 24, row_y + 7, 16, 12, icon_color);
            } else {
                fill_rect(x + 26, row_y + 5, 12, 16, icon_color);
            }

            unsafe {
                draw_string(x + 48, row_y + 8, &PICKER_FILES[i][..name_len], COLOR_TEXT_WHITE);
            }
        }
    }

    let btn_y = y + h - 48;

    draw_rounded_rect(x + w - 90, btn_y, 72, 32, 6, COLOR_BTN);
    draw_string(x + w - 76, btn_y + 10, b"Cancel", COLOR_TEXT_WHITE);

    draw_rounded_rect(x + w - 172, btn_y, 72, 32, 6, COLOR_ACCENT);
    draw_string(x + w - 160, btn_y + 10, b"Open", 0xFF000000);
}

pub(super) fn draw_toolbar(x: u32, y: u32, w: u32) {
    for gy in 0..TOOLBAR_HEIGHT {
        let shade = 44 - (gy / 2) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + TOOLBAR_HEIGHT - 1, w, 1, COLOR_BORDER);

    let tools: [(&[u8], u32); 4] = [
        (b"New", 48),
        (b"Open", 52),
        (b"Save", 52),
        (b"Close", 56),
    ];

    let mut tx = x + 12;
    for (tool, btn_w) in tools.iter() {
        draw_rounded_rect(tx, y + 6, *btn_w, 26, 6, COLOR_BTN);
        draw_string(tx + 10, y + 12, tool, COLOR_TEXT_WHITE);
        tx += btn_w + 10;
    }

    let status = EDITOR_STATUS.load(Ordering::Relaxed);
    let modified = is_modified();

    let status_x = x + w - 110;
    match status {
        STATUS_SAVED => {
            draw_rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF1A3A1A);
            draw_string(status_x + 24, y + 12, b"Saved", COLOR_GREEN);
        }
        STATUS_OPENED => {
            draw_rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF1A2A3A);
            draw_string(status_x + 20, y + 12, b"Opened", COLOR_ACCENT);
        }
        STATUS_ERROR => {
            draw_rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF3A1A1A);
            draw_string(status_x + 24, y + 12, b"Error", COLOR_RED);
        }
        STATUS_NEW => {
            draw_rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF1A2A3A);
            draw_string(status_x + 32, y + 12, b"New", COLOR_ACCENT);
        }
        _ => {
            if modified {
                draw_rounded_rect(status_x, y + 6, 90, 26, 6, 0xFF3A3500);
                draw_string(status_x + 12, y + 12, b"Modified", COLOR_YELLOW);
            }
        }
    }
}

pub(super) fn draw_line_numbers(x: u32, y: u32, h: u32) {
    fill_rect(x, y, LINE_NUM_WIDTH, h, 0xFF1C1C1E);
    fill_rect(x + LINE_NUM_WIDTH - 1, y, 1, h, COLOR_BORDER);
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

    for gy in 0..STATUS_BAR_HEIGHT {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, bar_y + gy, w, 1, color);
    }
    fill_rect(x, bar_y, w, 1, COLOR_BORDER);

    let path_len = EDITOR_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        let display_len = path_len.min(30);
        unsafe {
            draw_string(x + 12, bar_y + 8, &EDITOR_FILE_PATH[..display_len], COLOR_TEXT_DIM);
        }
    } else {
        draw_string(x + 12, bar_y + 8, b"untitled", COLOR_TEXT_DIM);
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

    draw_string(x + w - 130, bar_y + 8, &pos_buf[..idx], COLOR_TEXT_DIM);
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

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
use crate::graphics::components::text;
use super::state::*;
use super::cursor as cur;

pub fn draw_line_numbers(x: u32, y: u32, h: u32) {
    fill_rect(x, y, LINE_NUM_WIDTH, h, BG_SURFACE);
    fill_rect(x + LINE_NUM_WIDTH - 1, y, 1, h, BORDER_DEFAULT);
}

pub fn draw_line_number(x: u32, y: u32, num: usize) {
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
            draw_char(x + 5 + (j as u32) * 8, y, ch, TEXT_SECONDARY);
        }
    }
}

pub fn draw_status_bar(x: u32, y: u32, w: u32, h: u32) {
    let bar_y = y + h - STATUS_BAR_HEIGHT;
    for gy in 0..STATUS_BAR_HEIGHT {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, bar_y + gy, w, 1, color);
    }
    fill_rect(x, bar_y, w, 1, BORDER_DEFAULT);

    let path_len = EDITOR_PATH_LEN.load(Ordering::Relaxed);
    if path_len > 0 {
        let display_len = path_len.min(30);
        unsafe { text::draw(x + 12, bar_y + 8, &EDITOR_FILE_PATH[..display_len], TEXT_SECONDARY); }
    } else {
        text::draw(x + 12, bar_y + 8, b"untitled", TEXT_SECONDARY);
    }

    draw_position(x, bar_y, w);
}

fn draw_position(x: u32, bar_y: u32, w: u32) {
    let (line, col) = cur::get_line_col();
    let mut pos_buf = [0u8; 20];
    let mut idx = 0;
    pos_buf[idx..idx + 3].copy_from_slice(b"Ln ");
    idx += 3;
    idx += format_number(&mut pos_buf[idx..], line);
    pos_buf[idx..idx + 5].copy_from_slice(b" Col ");
    idx += 5;
    idx += format_number(&mut pos_buf[idx..], col);
    text::draw(x + w - 130, bar_y + 8, &pos_buf[..idx], TEXT_SECONDARY);
}

pub fn format_number(buf: &mut [u8], num: usize) -> usize {
    if num == 0 { buf[0] = b'0'; return 1; }
    let mut n = num;
    let mut digits = [0u8; 10];
    let mut count = 0;
    while n > 0 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    for i in 0..count { buf[i] = digits[count - 1 - i]; }
    count
}

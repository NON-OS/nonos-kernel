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

use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::font::draw_char;

pub(super) const COLOR_CARD_BG: u32 = 0xFF161B22;
pub(super) const COLOR_CARD_BORDER: u32 = 0xFF30363D;
pub(super) const COLOR_TEXT: u32 = 0xFFC9D1D9;
pub(super) const COLOR_TEXT_DIM: u32 = 0xFF8B949E;
pub(super) const COLOR_TEXT_BRIGHT: u32 = 0xFFFFFFFF;
pub(super) const COLOR_ACCENT: u32 = 0xFF238636;
pub(super) const COLOR_WARNING: u32 = 0xFFD29922;
pub(super) const COLOR_ERROR: u32 = 0xFFF85149;
pub(super) const COLOR_BUTTON: u32 = 0xFF238636;
pub(super) const COLOR_BUTTON_TEXT: u32 = 0xFFFFFFFF;
pub(super) const COLOR_INPUT_BG: u32 = 0xFF0D1117;
pub(super) const COLOR_INPUT_BORDER: u32 = 0xFF30363D;

pub(super) fn draw_card(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_CARD_BG);
    draw_border(x, y, w, h, COLOR_CARD_BORDER);
}

pub(super) fn draw_border(x: u32, y: u32, w: u32, h: u32, color: u32) {
    fill_rect(x, y, w, 1, color);
    fill_rect(x, y + h - 1, w, 1, color);
    fill_rect(x, y, 1, h, color);
    fill_rect(x + w - 1, y, 1, h, color);
}

pub(super) fn draw_button(x: u32, y: u32, w: u32, h: u32, label: &[u8]) {
    fill_rect(x, y, w, h, COLOR_BUTTON);

    let text_w = label.len() as u32 * 8;
    let text_x = x + (w.saturating_sub(text_w)) / 2;
    let text_y = y + (h.saturating_sub(16)) / 2;

    for (i, &ch) in label.iter().enumerate() {
        draw_char(text_x + i as u32 * 8, text_y, ch, COLOR_BUTTON_TEXT);
    }
}

pub(super) fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, color);
    }
}

pub(super) fn draw_string_clipped(x: u32, y: u32, text: &[u8], color: u32, max_width: u32) {
    let max_chars = (max_width / 8) as usize;
    let display_len = text.len().min(max_chars);
    for (i, &ch) in text[..display_len].iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, color);
    }
}

pub(super) fn draw_number(x: u32, y: u32, n: usize, color: u32) {
    let mut buf = [0u8; 20];
    let s = format_number(n, &mut buf);
    draw_string(x, y, s, color);
}

pub(super) fn format_number(mut n: usize, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[0..1];
    }

    let mut i = 19;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i -= 1;
    }
    &buf[i + 1..]
}

pub(super) fn draw_checkbox(x: u32, y: u32, checked: bool) {
    fill_rect(x, y, 20, 20, COLOR_INPUT_BG);
    draw_border(x, y, 20, 20, COLOR_INPUT_BORDER);

    if checked {
        fill_rect(x + 4, y + 4, 12, 12, COLOR_ACCENT);

        put_pixel(x + 6, y + 10, COLOR_BUTTON_TEXT);
        put_pixel(x + 7, y + 11, COLOR_BUTTON_TEXT);
        put_pixel(x + 8, y + 12, COLOR_BUTTON_TEXT);
        put_pixel(x + 9, y + 11, COLOR_BUTTON_TEXT);
        put_pixel(x + 10, y + 10, COLOR_BUTTON_TEXT);
        put_pixel(x + 11, y + 9, COLOR_BUTTON_TEXT);
        put_pixel(x + 12, y + 8, COLOR_BUTTON_TEXT);
        put_pixel(x + 13, y + 7, COLOR_BUTTON_TEXT);
    }
}

pub(super) fn draw_status_indicator(x: u32, y: u32, color: u32) {
    for dy in 0..12 {
        for dx in 0..12 {
            let dist_sq = (dx as i32 - 6) * (dx as i32 - 6) + (dy as i32 - 6) * (dy as i32 - 6);
            if dist_sq <= 36 {
                put_pixel(x + dx, y + dy, color);
            }
        }
    }
}

pub(super) fn draw_progress_bar(x: u32, y: u32, w: u32, h: u32, percent: u8) {
    fill_rect(x, y, w, h, COLOR_INPUT_BG);
    draw_border(x, y, w, h, COLOR_INPUT_BORDER);

    let fill_w = ((w - 4) as u32 * percent as u32) / 100;
    if fill_w > 0 {
        fill_rect(x + 2, y + 2, fill_w, h - 4, COLOR_ACCENT);
    }

    let mut buf = [0u8; 20];
    let pct_str = format_number(percent as usize, &mut buf);
    let text_w = pct_str.len() as u32 * 8 + 8;
    let text_x = x + (w - text_w) / 2;
    draw_string(text_x, y + 4, pct_str, COLOR_TEXT);
    draw_char(text_x + pct_str.len() as u32 * 8, y + 4, b'%', COLOR_TEXT);
}

pub(super) fn draw_spinner(x: u32, y: u32) {
    static mut SPINNER_FRAME: u8 = 0;

    // SAFETY: Single-threaded GUI context
    unsafe {
        SPINNER_FRAME = (SPINNER_FRAME + 1) % 8;
    }

    let chars = [b'|', b'/', b'-', b'\\', b'|', b'/', b'-', b'\\'];
    // SAFETY: Single-threaded GUI context
    let frame = unsafe { SPINNER_FRAME } as usize;

    draw_char(x, y, chars[frame], COLOR_ACCENT);
}

pub(super) fn draw_error_toast(x: u32, y: u32, w: u32, msg: &str) {
    let toast_w = (msg.len() as u32 * 8 + 40).min(w - 32);
    let toast_x = x + (w - toast_w) / 2;

    fill_rect(toast_x, y, toast_w, 40, COLOR_ERROR);

    let text_x = toast_x + 20;
    for (i, ch) in msg.bytes().take(((toast_w - 40) / 8) as usize).enumerate() {
        draw_char(text_x + i as u32 * 8, y + 12, ch, COLOR_BUTTON_TEXT);
    }
}

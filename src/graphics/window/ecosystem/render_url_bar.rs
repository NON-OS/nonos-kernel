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

use super::render_helpers::{
    draw_border, draw_string, COLOR_ACCENT, COLOR_CARD_BG, COLOR_CARD_BORDER, COLOR_INPUT_BG,
    COLOR_INPUT_BORDER, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_DIM,
};
use super::state;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

const COLOR_URL_BAR: u32 = 0xFF2C2C2E;
const COLOR_URL_TEXT: u32 = 0xFFFFFFFF;

pub fn draw_url_bar(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_URL_BAR);
    draw_border(x, y, w, h, COLOR_CARD_BORDER);
    let nav_btn_w = 28;
    draw_nav_button(x + 4, y + 4, nav_btn_w, h - 8, b"<");
    draw_nav_button(x + 4 + nav_btn_w + 4, y + 4, nav_btn_w, h - 8, b">");
    draw_nav_button(x + 4 + (nav_btn_w + 4) * 2, y + 4, nav_btn_w, h - 8, b"R");
    let url_x = x + 4 + (nav_btn_w + 4) * 3 + 8;
    let url_w = w - (url_x - x) - 8;
    draw_url_input(url_x, y, url_w, h);
}

fn draw_url_input(url_x: u32, y: u32, url_w: u32, h: u32) {
    let url_focused = state::URL_FOCUSED.load(Ordering::Relaxed);
    let is_https = state::IS_HTTPS.load(Ordering::Relaxed);
    let border_color = if url_focused { COLOR_ACCENT } else { COLOR_INPUT_BORDER };
    fill_rect(url_x, y + 4, url_w, h - 8, COLOR_INPUT_BG);
    draw_border(url_x, y + 4, url_w, h - 8, border_color);
    let lock_x = url_x + 6;
    let text_start = if is_https { url_x + 22 } else { url_x + 8 };
    if is_https {
        draw_char(lock_x, y + 12, b'S', COLOR_ACCENT);
    }
    draw_url_text(text_start, y, url_w - (text_start - url_x) - 8, url_focused);
}

fn draw_url_text(text_start: u32, y: u32, available_w: u32, url_focused: bool) {
    let url_buf = state::URL_BUFFER.lock();
    let url_len = state::URL_LEN.load(Ordering::Relaxed);
    let url_cursor = state::URL_CURSOR.load(Ordering::Relaxed);
    if url_len > 0 {
        let max_chars = (available_w / 8) as usize;
        let display_len = url_len.min(max_chars);
        for (i, &ch) in url_buf[..display_len].iter().enumerate() {
            draw_char(text_start + i as u32 * 8, y + 12, ch, COLOR_URL_TEXT);
        }
    } else {
        draw_string(text_start, y + 12, b"Enter URL...", COLOR_TEXT_DIM);
    }
    if url_focused {
        let cursor_x = text_start + (url_cursor as u32) * 8;
        fill_rect(cursor_x, y + 8, 2, 20, COLOR_TEXT_BRIGHT);
    }
}

fn draw_nav_button(x: u32, y: u32, w: u32, h: u32, label: &[u8]) {
    fill_rect(x, y, w, h, COLOR_CARD_BG);
    let text_x = x + (w.saturating_sub(label.len() as u32 * 8)) / 2;
    let text_y = y + (h.saturating_sub(16)) / 2;
    for (i, &ch) in label.iter().enumerate() {
        draw_char(text_x + i as u32 * 8, text_y, ch, COLOR_TEXT);
    }
}

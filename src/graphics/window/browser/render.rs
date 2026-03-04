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

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::Ordering;

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::font::draw_char;
use crate::graphics::window::draw_string;

use super::constants::*;
use super::state::*;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    draw_toolbar(x, y, w);
    draw_content(x, y + TOOLBAR_HEIGHT, w, h.saturating_sub(TOOLBAR_HEIGHT + STATUS_BAR_HEIGHT));
    draw_status_bar(x, y + h - STATUS_BAR_HEIGHT, w);
}

fn draw_toolbar(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, TOOLBAR_HEIGHT, COLOR_TOOLBAR_BG);

    let back_enabled = can_go_back();
    let forward_enabled = can_go_forward();

    let back_x = x + 10;
    let back_color = if back_enabled { COLOR_BUTTON_ACTIVE } else { COLOR_BUTTON_INACTIVE };
    let back_text_color = if back_enabled { COLOR_TEXT_WHITE } else { COLOR_DISABLED };
    fill_rect(back_x, y + 8, BUTTON_WIDTH, BUTTON_HEIGHT, back_color);
    draw_char(back_x + 8, y + 12, b'<', back_text_color);

    let fwd_x = x + 40;
    let fwd_color = if forward_enabled { COLOR_BUTTON_ACTIVE } else { COLOR_BUTTON_INACTIVE };
    let fwd_text_color = if forward_enabled { COLOR_TEXT_WHITE } else { COLOR_DISABLED };
    fill_rect(fwd_x, y + 8, BUTTON_WIDTH, BUTTON_HEIGHT, fwd_color);
    draw_char(fwd_x + 8, y + 12, b'>', fwd_text_color);

    let refresh_x = x + 70;
    fill_rect(refresh_x, y + 8, BUTTON_WIDTH, BUTTON_HEIGHT, COLOR_BUTTON_ACTIVE);
    draw_char(refresh_x + 8, y + 12, b'R', COLOR_TEXT_WHITE);

    let url_bar_x = x + 105;
    let url_bar_w = w.saturating_sub(175);
    let url_focused = URL_FOCUSED.load(Ordering::Relaxed);
    let url_border = if url_focused { COLOR_ACCENT } else { COLOR_URL_BAR_BORDER };

    fill_rect(url_bar_x - 1, y + 7, url_bar_w + 2, BUTTON_HEIGHT + 2, url_border);
    fill_rect(url_bar_x, y + 8, url_bar_w, BUTTON_HEIGHT, COLOR_URL_BAR_BG);

    draw_url_text(url_bar_x, y, url_bar_w, url_focused);

    let go_x = x + w - 60;
    let loading = LOADING.load(Ordering::Relaxed);
    let go_color = if loading { COLOR_BUTTON_INACTIVE } else { COLOR_ACCENT };
    fill_rect(go_x, y + 8, 50, BUTTON_HEIGHT, go_color);

    let go_text: &[u8] = if loading { b"..." } else { b"Go" };
    let text_offset = if loading { 16 } else { 20 };
    draw_string(go_x + text_offset, y + 12, go_text, 0xFF0D1117);
}

fn draw_url_text(url_bar_x: u32, y: u32, url_bar_w: u32, focused: bool) {
    let url_buf = URL_BUFFER.lock();
    let url_len = URL_LEN.load(Ordering::Relaxed);
    let cursor = URL_CURSOR.load(Ordering::Relaxed);
    let max_chars = ((url_bar_w - 16) / 8) as usize;

    let (start, display_cursor) = if cursor > max_chars {
        (cursor - max_chars, max_chars)
    } else {
        (0, cursor)
    };

    let end = (start + max_chars).min(url_len);
    for (i, &ch) in url_buf[start..end].iter().enumerate() {
        draw_char(url_bar_x + 8 + (i as u32) * 8, y + 12, ch, COLOR_TEXT_WHITE);
    }

    if focused {
        let cursor_x = url_bar_x + 8 + (display_cursor as u32) * 8;
        fill_rect(cursor_x, y + 10, 2, 16, COLOR_ACCENT);
    }
}

fn draw_content(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_CONTENT_BG);

    let lines = PAGE_LINES.lock();
    let scroll = SCROLL_OFFSET.load(Ordering::Relaxed);
    let visible_lines = (h / 16) as usize;
    let max_chars = ((w - 32) / 8) as usize;

    if lines.is_empty() {
        draw_welcome_message(x, y, w, h);
    } else {
        for (i, (line, color)) in lines.iter().skip(scroll).take(visible_lines).enumerate() {
            let line_y = y + 8 + (i as u32) * 16;
            let display: String = if line.len() > max_chars {
                line.chars().take(max_chars).collect()
            } else {
                line.clone()
            };

            for (j, ch) in display.bytes().enumerate() {
                if ch >= 0x20 && ch < 0x7F {
                    draw_char(x + 16 + (j as u32) * 8, line_y, ch, *color);
                }
            }
        }

        if lines.len() > visible_lines {
            draw_scrollbar(x + w - 12, y, h, scroll, lines.len(), visible_lines);
        }
    }
}

fn draw_welcome_message(x: u32, y: u32, w: u32, h: u32) {
    let msg_y = y + h / 2 - 50;
    draw_string(x + w / 2 - 56, msg_y, b"N\xd8NOS Browser", COLOR_ACCENT);
    draw_string(x + w / 2 - 100, msg_y + 25, b"Privacy-Focused Browsing", COLOR_GREEN);
    draw_string(x + w / 2 - 112, msg_y + 50, b"Enter a URL above to begin", COLOR_STATUS_TEXT);
    draw_string(x + w / 2 - 96, msg_y + 75, b"Try: example.com", 0xFF5A6370);
}

fn draw_scrollbar(x: u32, y: u32, h: u32, scroll: usize, total_lines: usize, visible_lines: usize) {
    fill_rect(x, y, 10, h, COLOR_SCROLLBAR_BG);

    let thumb_h = (visible_lines as u32 * h / total_lines as u32).max(20);
    let max_scroll = total_lines.saturating_sub(visible_lines);
    let thumb_y = if max_scroll > 0 {
        y + (scroll as u32 * (h - thumb_h) / max_scroll as u32)
    } else {
        y
    };

    fill_rect(x + 2, thumb_y, 6, thumb_h, COLOR_SCROLLBAR_THUMB);
}

fn draw_status_bar(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, STATUS_BAR_HEIGHT, COLOR_STATUS_BG);

    let status = STATUS_MSG.lock();
    let status_len = STATUS_LEN.load(Ordering::Relaxed);

    if status_len > 0 {
        for (i, &ch) in status[..status_len].iter().enumerate() {
            draw_char(x + 10 + (i as u32) * 8, y + 7, ch, COLOR_STATUS_TEXT);
        }
    } else {
        draw_string(x + 10, y + 7, b"Ready", COLOR_STATUS_TEXT);
    }

    let indicator_x = x + w - 100;
    let connected = crate::network::get_network_stack().is_some();

    if connected {
        fill_rect(indicator_x, y + 10, 8, 8, COLOR_GREEN);
        draw_string(indicator_x + 12, y + 7, b"Connected", COLOR_STATUS_TEXT);
    } else {
        fill_rect(indicator_x, y + 10, 8, 8, 0xFFFF6B6B);
        draw_string(indicator_x + 12, y + 7, b"Offline", COLOR_STATUS_TEXT);
    }
}

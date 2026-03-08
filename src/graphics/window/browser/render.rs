// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::Ordering;

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::font::draw_char;
use crate::graphics::window::draw_string;

use super::constants::*;
use super::state::*;
use super::find::{is_match_position, is_current_match_position, get_pattern_len};

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    draw_toolbar(x, y, w);
    draw_content(x, y + TOOLBAR_HEIGHT, w, h.saturating_sub(TOOLBAR_HEIGHT + STATUS_BAR_HEIGHT));
    draw_status_bar(x, y + h - STATUS_BAR_HEIGHT, w);
}

fn draw_toolbar(x: u32, y: u32, w: u32) {
    for gy in 0..TOOLBAR_HEIGHT {
        let shade = 44 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + TOOLBAR_HEIGHT - 1, w, 1, 0xFF1C1C1E);

    let back_enabled = can_go_back();
    let forward_enabled = can_go_forward();

    let btn_y = y + 10;
    let back_x = x + 12;
    draw_round_button(back_x, btn_y, back_enabled);
    draw_arrow(back_x + 10, btn_y + 10, true, if back_enabled { COLOR_TEXT_WHITE } else { COLOR_DISABLED });

    let fwd_x = x + 48;
    draw_round_button(fwd_x, btn_y, forward_enabled);
    draw_arrow(fwd_x + 12, btn_y + 10, false, if forward_enabled { COLOR_TEXT_WHITE } else { COLOR_DISABLED });

    let refresh_x = x + 84;
    draw_round_button(refresh_x, btn_y, true);
    draw_refresh_icon(refresh_x + 11, btn_y + 11, COLOR_TEXT_WHITE);

    let url_bar_x = x + 130;
    let url_bar_w = w.saturating_sub(210);
    let url_focused = URL_FOCUSED.load(Ordering::Relaxed);

    draw_url_bar(url_bar_x, btn_y, url_bar_w, url_focused);
    draw_url_text(url_bar_x, y, url_bar_w, url_focused);

    let go_x = x + w - 70;
    let loading = LOADING.load(Ordering::Relaxed);
    draw_go_button(go_x, btn_y, loading);
}

fn draw_round_button(x: u32, y: u32, enabled: bool) {
    let color = if enabled { COLOR_BUTTON_ACTIVE } else { COLOR_BUTTON_INACTIVE };
    let r = 6u32;
    fill_rect(x + r, y, BUTTON_WIDTH - 2 * r, BUTTON_HEIGHT, color);
    fill_rect(x, y + r, BUTTON_WIDTH, BUTTON_HEIGHT - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + BUTTON_WIDTH - r + dx - 1, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + BUTTON_HEIGHT - r + dy - 1, color);
        crate::graphics::framebuffer::put_pixel(x + BUTTON_WIDTH - r + dx - 1, y + BUTTON_HEIGHT - r + dy - 1, color);
    }}}
}

fn draw_arrow(x: u32, y: u32, left: bool, color: u32) {
    for i in 0..5u32 {
        let w = 5 - i;
        let px = if left { x + i } else { x + 4 - i };
        fill_rect(px, y - w as u32, 2, w * 2 + 1, color);
    }
}

fn draw_refresh_icon(x: u32, y: u32, color: u32) {
    let offsets: [(i32, i32); 8] = [
        (5, 0), (3, 3), (0, 5), (-3, 3),
        (-5, 0), (-3, -3), (0, -5), (3, -3),
    ];
    for (ax, ay) in offsets.iter() {
        crate::graphics::framebuffer::put_pixel((x as i32 + ax) as u32, (y as i32 + ay) as u32, color);
    }
}

fn draw_url_bar(x: u32, y: u32, w: u32, focused: bool) {
    let border_color = if focused { 0xFF007AFF } else { COLOR_URL_BAR_BORDER };
    let r = 8u32;
    fill_rect(x + r, y - 1, w - 2 * r, BUTTON_HEIGHT + 2, border_color);
    fill_rect(x - 1, y + r - 1, w + 2, BUTTON_HEIGHT - 2 * r + 2, border_color);
    fill_rect(x + r, y, w - 2 * r, BUTTON_HEIGHT, COLOR_URL_BAR_BG);
    fill_rect(x, y + r, w, BUTTON_HEIGHT - 2 * r, COLOR_URL_BAR_BG);
}

fn draw_go_button(x: u32, y: u32, loading: bool) {
    let color = if loading { 0xFF48484A } else { 0xFF007AFF };
    let r = 8u32;
    let w = 56u32;
    fill_rect(x + r, y, w - 2 * r, BUTTON_HEIGHT, color);
    fill_rect(x, y + r, w, BUTTON_HEIGHT - 2 * r, color);
    let text: &[u8] = if loading { b"..." } else { b"Go" };
    let tx = x + w / 2 - (text.len() as u32 * 8) / 2;
    draw_string(tx, y + 10, text, 0xFFFFFFFF);
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
        let pattern_len = get_pattern_len();
        for (i, (line, color)) in lines.iter().skip(scroll).take(visible_lines).enumerate() {
            let line_idx = scroll + i;
            let line_y = y + 8 + (i as u32) * 16;
            let display: String = if line.len() > max_chars {
                line.chars().take(max_chars).collect()
            } else {
                line.clone()
            };

            for (j, ch) in display.bytes().enumerate() {
                if ch >= 0x20 && ch < 0x7F {
                    let char_x = x + 16 + (j as u32) * 8;
                    if pattern_len > 0 && is_current_match_position(line_idx, j) {
                        fill_rect(char_x, line_y, 8, 16, 0xFFD29922);
                        draw_char(char_x, line_y, ch, 0xFF0D1117);
                    } else if pattern_len > 0 && is_match_position(line_idx, j) {
                        fill_rect(char_x, line_y, 8, 16, 0xFF3D4A3A);
                        draw_char(char_x, line_y, ch, COLOR_TEXT_WHITE);
                    } else {
                        draw_char(char_x, line_y, ch, *color);
                    }
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

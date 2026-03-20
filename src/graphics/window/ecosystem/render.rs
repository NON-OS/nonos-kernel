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

use alloc::string::{String, ToString};
use core::sync::atomic::Ordering;

use super::state::{self, EcosystemTab};
use super::tabs;
use super::render_helpers::{
    draw_border, draw_string, draw_spinner, draw_error_toast,
    COLOR_CARD_BG, COLOR_CARD_BORDER, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_BRIGHT,
    COLOR_ACCENT, COLOR_WARNING, COLOR_INPUT_BG, COLOR_INPUT_BORDER,
};
use super::render_tabs::{
    draw_wallet_tab, draw_staking_tab, draw_lp_tab, draw_node_tab, draw_privacy_tab,
};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::font::draw_char;

const COLOR_BG: u32 = 0xFF000000;
const COLOR_URL_BAR: u32 = 0xFF2C2C2E;
const COLOR_URL_TEXT: u32 = 0xFFFFFFFF;
const COLOR_CODE_BG: u32 = 0xFF2C2C2E;
const COLOR_CODE_FG: u32 = 0xFFFF8C00;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);

    let active_tab = state::get_active_tab();
    tabs::draw_tab_bar(x, y, w, active_tab);

    let content_y = y + tabs::TAB_HEIGHT;
    let content_h = h.saturating_sub(tabs::TAB_HEIGHT);

    match active_tab {
        EcosystemTab::Browser => draw_browser_tab(x, content_y, w, content_h),
        EcosystemTab::Wallet => draw_wallet_tab(x, content_y, w, content_h),
        EcosystemTab::Staking => draw_staking_tab(x, content_y, w, content_h),
        EcosystemTab::Liquidity => draw_lp_tab(x, content_y, w, content_h),
        EcosystemTab::Node => draw_node_tab(x, content_y, w, content_h),
        EcosystemTab::Privacy => draw_privacy_tab(x, content_y, w, content_h),
    }

    if let Some(error) = state::get_error() {
        draw_error_toast(x, y + h - 60, w, &error);
    }
}

const COLOR_LINK: u32 = 0xFF00BFFF;
const COLOR_HEADING: u32 = 0xFF00FFCC;
const COLOR_SCROLLBAR: u32 = 0xFF48484A;
const COLOR_SCROLLBAR_THUMB: u32 = 0xFF00FFCC;

fn draw_browser_tab(x: u32, y: u32, w: u32, h: u32) {
    draw_url_bar(x + 8, y + 8, w - 16, 36);

    let content_y = y + 52;
    let content_h = h.saturating_sub(60);

    fill_rect(x + 8, content_y, w - 16, content_h, COLOR_CARD_BG);
    draw_border(x + 8, content_y, w - 16, content_h, COLOR_CARD_BORDER);

    let loading = state::LOADING.load(Ordering::Relaxed);
    if loading {
        draw_string(x + 20, content_y + 20, b"Loading...", COLOR_TEXT_DIM);
        draw_spinner(x + w / 2 - 16, content_y + content_h / 2 - 16);
    } else {
        let content = state::PAGE_CONTENT.lock();
        let scroll = state::PAGE_SCROLL.load(Ordering::Relaxed);
        let total_lines = state::PAGE_TOTAL_LINES.load(Ordering::Relaxed);
        let visible_lines = (content_h.saturating_sub(16) / 18) as usize;

        if content.is_empty() {
            draw_string(x + 20, content_y + 20, b"Enter a URL to browse the web", COLOR_TEXT_DIM);
            draw_string(x + 20, content_y + 44, b"Privacy features enabled:", COLOR_TEXT);
            draw_string(x + 20, content_y + 68, b"  - Tracker blocking", COLOR_ACCENT);
            draw_string(x + 20, content_y + 92, b"  - URL parameter stripping", COLOR_ACCENT);
            draw_string(x + 20, content_y + 116, b"  - JavaScript disabled by default", COLOR_ACCENT);
            draw_string(x + 20, content_y + 156, b"Keyboard shortcuts:", COLOR_TEXT);
            draw_string(x + 20, content_y + 180, b"  Page Up/Down - Scroll page", COLOR_TEXT_DIM);
            draw_string(x + 20, content_y + 204, b"  Enter - Navigate to URL", COLOR_TEXT_DIM);
        } else {
            for (i, line) in content.iter().skip(scroll).take(visible_lines).enumerate() {
                let line_y = content_y + 8 + i as u32 * 18;
                draw_styled_line(x + 16, line_y, line.as_bytes(), w - 48);
            }

            if total_lines > visible_lines {
                draw_scrollbar(x + w - 24, content_y + 4, 8, content_h - 8, scroll, total_lines, visible_lines);
            }

            if let Some(title) = state::get_page_title() {
                let title_bytes = title.as_bytes();
                let max_title = ((w - 100) / 8) as usize;
                let display_len = title_bytes.len().min(max_title);
                draw_string(x + 16, content_y + content_h - 20, &title_bytes[..display_len], COLOR_TEXT_DIM);
            }
        }
    }
}

fn draw_scrollbar(x: u32, y: u32, w: u32, h: u32, scroll: usize, total: usize, visible: usize) {
    fill_rect(x, y, w, h, COLOR_SCROLLBAR);

    if total > 0 {
        let thumb_h = ((visible as u32 * h) / total as u32).max(20).min(h);
        let thumb_y = if total > visible {
            y + ((scroll as u32 * (h - thumb_h)) / (total - visible) as u32)
        } else {
            y
        };
        fill_rect(x, thumb_y, w, thumb_h, COLOR_SCROLLBAR_THUMB);
    }
}

fn draw_styled_line(x: u32, y: u32, text: &[u8], max_width: u32) {
    let max_chars = (max_width / 8) as usize;
    let mut current_x = x;
    let mut i = 0;
    let mut char_count = 0;
    let mut is_heading = false;
    let mut is_bold = false;

    if text.len() >= 3 && &text[0..3] == b"## " {
        is_heading = true;
        i = 3;
    }

    while i < text.len() && char_count < max_chars {
        if i + 2 <= text.len() && &text[i..i+2] == b"**" {
            is_bold = !is_bold;
            i += 2;
            continue;
        }

        if i + 5 < text.len() && &text[i..i+5] == b"[http" {
            let start = i;
            while i < text.len() && text[i] != b']' {
                i += 1;
            }
            if i < text.len() {
                i += 1;
            }
            for &ch in &text[start..i] {
                if char_count >= max_chars {
                    break;
                }
                draw_char(current_x, y, ch, COLOR_LINK);
                current_x += 8;
                char_count += 1;
            }
        } else if i + 4 < text.len() && &text[i..i+4] == b"[IMG" {
            let start = i;
            while i < text.len() && text[i] != b']' {
                i += 1;
            }
            if i < text.len() {
                i += 1;
            }
            for &ch in &text[start..i] {
                if char_count >= max_chars {
                    break;
                }
                draw_char(current_x, y, ch, COLOR_TEXT_DIM);
                current_x += 8;
                char_count += 1;
            }
        } else if i + 4 < text.len() && &text[i..i+4] == b"[BTN" {
            let start = i;
            while i < text.len() && text[i] != b']' {
                i += 1;
            }
            if i < text.len() {
                i += 1;
            }
            for &ch in &text[start..i] {
                if char_count >= max_chars {
                    break;
                }
                draw_char(current_x, y, ch, COLOR_ACCENT);
                current_x += 8;
                char_count += 1;
            }
        } else if i + 6 < text.len() && &text[i..i+6] == b"[INPUT" {
            let start = i;
            while i < text.len() && text[i] != b']' {
                i += 1;
            }
            if i < text.len() {
                i += 1;
            }
            for &ch in &text[start..i] {
                if char_count >= max_chars {
                    break;
                }
                draw_char(current_x, y, ch, COLOR_WARNING);
                current_x += 8;
                char_count += 1;
            }
        } else if text[i] == 0xE2 && i + 2 < text.len() {
            draw_char(current_x, y, b'-', COLOR_TEXT_DIM);
            current_x += 8;
            char_count += 1;
            i += 3;
        } else if text[i] == b'`' {
            // Code span: draw with dark background
            i += 1;
            let code_start_x = current_x;
            while i < text.len() && text[i] != b'`' && char_count < max_chars {
                draw_char(current_x, y, text[i], COLOR_CODE_FG);
                current_x += 8;
                char_count += 1;
                i += 1;
            }
            // Fill background behind code chars
            let code_w = current_x.saturating_sub(code_start_x);
            if code_w > 0 {
                fill_rect(code_start_x, y, code_w, 16, COLOR_CODE_BG);
                // Re-draw chars on top of background
                let mut rx = code_start_x;
                let re_start = i.saturating_sub((code_w / 8) as usize);
                for &ch in &text[re_start..i] {
                    draw_char(rx, y, ch, COLOR_CODE_FG);
                    rx += 8;
                }
            }
            if i < text.len() && text[i] == b'`' {
                i += 1;
            }
        } else {
            let color = if is_heading {
                COLOR_HEADING
            } else if is_bold {
                COLOR_TEXT_BRIGHT
            } else {
                COLOR_TEXT
            };
            draw_char(current_x, y, text[i], color);
            current_x += 8;
            char_count += 1;
            i += 1;
        }
    }
}

fn draw_url_bar(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_URL_BAR);
    draw_border(x, y, w, h, COLOR_CARD_BORDER);

    let nav_btn_w = 28;
    draw_nav_button(x + 4, y + 4, nav_btn_w, h - 8, b"<");
    draw_nav_button(x + 4 + nav_btn_w + 4, y + 4, nav_btn_w, h - 8, b">");
    draw_nav_button(x + 4 + (nav_btn_w + 4) * 2, y + 4, nav_btn_w, h - 8, b"R");

    let url_x = x + 4 + (nav_btn_w + 4) * 3 + 8;
    let url_w = w - (url_x - x) - 8;

    let url_focused = state::URL_FOCUSED.load(Ordering::Relaxed);
    let is_https = state::IS_HTTPS.load(Ordering::Relaxed);
    let border_color = if url_focused { COLOR_ACCENT } else { COLOR_INPUT_BORDER };

    fill_rect(url_x, y + 4, url_w, h - 8, COLOR_INPUT_BG);
    draw_border(url_x, y + 4, url_w, h - 8, border_color);

    let lock_x = url_x + 6;
    let text_start = if is_https { url_x + 22 } else { url_x + 8 };

    if is_https {
        draw_char(lock_x, y + 12, 0xE2, COLOR_ACCENT);
        draw_char(lock_x + 8, y + 12, b'S', COLOR_ACCENT);
    }

    let url_buf = state::URL_BUFFER.lock();
    let url_len = state::URL_LEN.load(Ordering::Relaxed);
    let url_cursor = state::URL_CURSOR.load(Ordering::Relaxed);

    let available_w = url_w - (text_start - url_x) - 8;
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
        fill_rect(cursor_x, y + 8, 2, h - 16, COLOR_TEXT_BRIGHT);
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

pub fn format_balance(wei: u128) -> String {
    let eth = wei / 1_000_000_000_000_000_000;
    let gwei = (wei / 1_000_000_000) % 1_000_000_000;
    alloc::format!("{}.{:09}", eth, gwei)
}

pub fn format_status(connected: bool) -> String {
    if connected {
        "Connected".to_string()
    } else {
        "Disconnected".to_string()
    }
}

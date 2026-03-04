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
    draw_border, draw_string, draw_string_clipped, draw_spinner, draw_error_toast,
    COLOR_CARD_BG, COLOR_CARD_BORDER, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_BRIGHT,
    COLOR_ACCENT, COLOR_INPUT_BG, COLOR_INPUT_BORDER,
};
use super::render_tabs::{
    draw_wallet_tab, draw_staking_tab, draw_lp_tab, draw_node_tab, draw_privacy_tab,
};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::font::draw_char;

const COLOR_BG: u32 = 0xFF0D1117;
const COLOR_URL_BAR: u32 = 0xFF21262D;
const COLOR_URL_TEXT: u32 = 0xFFC9D1D9;

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
        let visible_lines = (content_h.saturating_sub(16) / 18) as usize;

        if content.is_empty() {
            draw_string(x + 20, content_y + 20, b"Enter a URL to browse the web", COLOR_TEXT_DIM);
            draw_string(x + 20, content_y + 44, b"Privacy features enabled:", COLOR_TEXT);
            draw_string(x + 20, content_y + 68, b"  - Tracker blocking", COLOR_ACCENT);
            draw_string(x + 20, content_y + 92, b"  - URL parameter stripping", COLOR_ACCENT);
            draw_string(x + 20, content_y + 116, b"  - JavaScript disabled by default", COLOR_ACCENT);
        } else {
            for (i, line) in content.iter().skip(scroll).take(visible_lines).enumerate() {
                draw_string_clipped(
                    x + 16,
                    content_y + 8 + i as u32 * 18,
                    line.as_bytes(),
                    COLOR_TEXT,
                    w - 32,
                );
            }
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
    let border_color = if url_focused { COLOR_ACCENT } else { COLOR_INPUT_BORDER };

    fill_rect(url_x, y + 4, url_w, h - 8, COLOR_INPUT_BG);
    draw_border(url_x, y + 4, url_w, h - 8, border_color);

    let url_buf = state::URL_BUFFER.lock();
    let url_len = state::URL_LEN.load(Ordering::Relaxed);
    let url_cursor = state::URL_CURSOR.load(Ordering::Relaxed);

    if url_len > 0 {
        let max_chars = ((url_w - 16) / 8) as usize;
        let display_len = url_len.min(max_chars);
        for (i, &ch) in url_buf[..display_len].iter().enumerate() {
            draw_char(url_x + 8 + i as u32 * 8, y + 12, ch, COLOR_URL_TEXT);
        }
    } else {
        draw_string(url_x + 8, y + 12, b"Enter URL...", COLOR_TEXT_DIM);
    }

    if url_focused {
        let cursor_x = url_x + 8 + (url_cursor as u32) * 8;
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

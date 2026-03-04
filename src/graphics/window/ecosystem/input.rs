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

use core::sync::atomic::Ordering;

use super::state::{self, EcosystemTab};
use super::tabs;
use super::input_actions::navigate_to_url;
use super::input_click::{
    handle_browser_click, handle_wallet_click, handle_staking_click,
    handle_lp_click, handle_node_click, handle_privacy_click,
};
use crate::graphics::window::text_editor::SpecialKey;

pub fn handle_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    let rel_x = click_x - win_x as i32;
    let rel_y = click_y - win_y as i32;

    if rel_x < 0 || rel_y < 0 {
        return false;
    }

    let rel_x = rel_x as u32;
    let rel_y = rel_y as u32;

    if rel_y < tabs::TAB_HEIGHT {
        if let Some(tab) = tabs::hit_test(0, 0, win_w, rel_x as i32, rel_y as i32) {
            state::set_active_tab(tab);
            return true;
        }
    }

    let content_y = tabs::TAB_HEIGHT;
    let content_rel_y = rel_y.saturating_sub(content_y);

    match state::get_active_tab() {
        EcosystemTab::Browser => handle_browser_click(rel_x, content_rel_y, win_w, win_h - content_y),
        EcosystemTab::Wallet => handle_wallet_click(rel_x, content_rel_y, win_w, win_h - content_y),
        EcosystemTab::Staking => handle_staking_click(rel_x, content_rel_y, win_w, win_h - content_y),
        EcosystemTab::Liquidity => handle_lp_click(rel_x, content_rel_y, win_w, win_h - content_y),
        EcosystemTab::Node => handle_node_click(rel_x, content_rel_y, win_w, win_h - content_y),
        EcosystemTab::Privacy => handle_privacy_click(rel_x, content_rel_y, win_w, win_h - content_y),
    }
}

pub fn handle_key(ch: u8) {
    match state::get_active_tab() {
        EcosystemTab::Browser => handle_browser_key(ch),
        EcosystemTab::Wallet => handle_wallet_key(ch),
        _ => {}
    }
}

fn handle_browser_key(ch: u8) {
    if !state::URL_FOCUSED.load(Ordering::Relaxed) {
        return;
    }

    let mut url_buf = state::URL_BUFFER.lock();
    let mut url_len = state::URL_LEN.load(Ordering::Relaxed);
    let mut cursor = state::URL_CURSOR.load(Ordering::Relaxed);

    match ch {
        0x08 | 0x7F => {
            if cursor > 0 && url_len > 0 {
                for i in cursor - 1..url_len - 1 {
                    url_buf[i] = url_buf[i + 1];
                }
                url_len -= 1;
                cursor -= 1;
            }
        }
        b'\r' | b'\n' => {
            drop(url_buf);
            navigate_to_url();
            return;
        }
        0x1B => {
            state::URL_FOCUSED.store(false, Ordering::Relaxed);
            state::set_input_focused(false);
        }
        _ if ch >= 0x20 && ch < 0x7F => {
            if url_len < state::MAX_URL_LEN - 1 {
                for i in (cursor..url_len).rev() {
                    url_buf[i + 1] = url_buf[i];
                }
                url_buf[cursor] = ch;
                url_len += 1;
                cursor += 1;
            }
        }
        _ => {}
    }

    state::URL_LEN.store(url_len, Ordering::Relaxed);
    state::URL_CURSOR.store(cursor, Ordering::Relaxed);
}

fn handle_wallet_key(key: u8) {
    if key == b'\n' || key == b'\r' {
        crate::graphics::window::notify_info(b"Wallet action triggered");
    }
}

pub fn handle_special_key(key: SpecialKey) {
    match state::get_active_tab() {
        EcosystemTab::Browser => handle_browser_special_key(key),
        _ => {}
    }
}

fn handle_browser_special_key(key: SpecialKey) {
    if !state::URL_FOCUSED.load(Ordering::Relaxed) {
        match key {
            SpecialKey::Up => scroll_page(-1),
            SpecialKey::Down => scroll_page(1),
            SpecialKey::PageUp => scroll_page(-10),
            SpecialKey::PageDown => scroll_page(10),
            SpecialKey::Home => state::PAGE_SCROLL.store(0, Ordering::Relaxed),
            _ => {}
        }
        return;
    }

    let url_len = state::URL_LEN.load(Ordering::Relaxed);
    let cursor = state::URL_CURSOR.load(Ordering::Relaxed);

    match key {
        SpecialKey::Left => {
            if cursor > 0 {
                state::URL_CURSOR.store(cursor - 1, Ordering::Relaxed);
            }
        }
        SpecialKey::Right => {
            if cursor < url_len {
                state::URL_CURSOR.store(cursor + 1, Ordering::Relaxed);
            }
        }
        SpecialKey::Home => {
            state::URL_CURSOR.store(0, Ordering::Relaxed);
        }
        SpecialKey::End => {
            state::URL_CURSOR.store(url_len, Ordering::Relaxed);
        }
        SpecialKey::Delete => {
            if cursor < url_len {
                let mut url_buf = state::URL_BUFFER.lock();
                for i in cursor..url_len - 1 {
                    url_buf[i] = url_buf[i + 1];
                }
                state::URL_LEN.store(url_len - 1, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

fn scroll_page(delta: i32) {
    let current = state::PAGE_SCROLL.load(Ordering::Relaxed) as i32;
    let content = state::PAGE_CONTENT.lock();
    let max_scroll = content.len().saturating_sub(20);
    drop(content);

    let new_scroll = (current + delta).max(0).min(max_scroll as i32) as usize;
    state::PAGE_SCROLL.store(new_scroll, Ordering::Relaxed);
}

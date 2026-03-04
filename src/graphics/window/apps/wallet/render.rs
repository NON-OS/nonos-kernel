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
use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE, COLOR_ACCENT};
use crate::graphics::window::draw_string;

use super::state::*;
use super::types::truncate_address;
use super::render_views::{draw_overview, draw_send_view, draw_receive_view, draw_transactions_view, draw_status_bar};
use super::render_stealth::{draw_stealth_view, draw_settings_view};

pub(super) const COLOR_BG: u32 = 0xFF0D1117;
pub(super) const COLOR_SIDEBAR: u32 = 0xFF161B22;
pub(super) const COLOR_CARD: u32 = 0xFF21262D;
pub(super) const COLOR_BORDER: u32 = 0xFF30363D;
pub(super) const COLOR_TEXT_DIM: u32 = 0xFF8B949E;
pub(super) const COLOR_YELLOW: u32 = 0xFFF0C674;
pub(super) const COLOR_RED: u32 = 0xFFFF6B6B;

const SIDEBAR_WIDTH: u32 = 180;
const HEADER_HEIGHT: u32 = 60;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);

    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        draw_locked_view(x, y, w, h);
        return;
    }

    let view = get_view();
    drop(state);

    draw_sidebar(x, y, h);
    draw_header(x + SIDEBAR_WIDTH, y, w - SIDEBAR_WIDTH);

    let content_x = x + SIDEBAR_WIDTH;
    let content_y = y + HEADER_HEIGHT;
    let content_w = w - SIDEBAR_WIDTH;
    let content_h = h - HEADER_HEIGHT - 30;

    match view {
        WalletView::Overview => draw_overview(content_x, content_y, content_w, content_h),
        WalletView::Send => draw_send_view(content_x, content_y, content_w, content_h),
        WalletView::Receive => draw_receive_view(content_x, content_y, content_w, content_h),
        WalletView::Transactions => draw_transactions_view(content_x, content_y, content_w, content_h),
        WalletView::Settings => draw_settings_view(content_x, content_y, content_w, content_h),
        WalletView::Stealth => draw_stealth_view(content_x, content_y, content_w, content_h),
    }

    draw_status_bar(x + SIDEBAR_WIDTH, y + h - 30, w - SIDEBAR_WIDTH);
}

fn draw_locked_view(x: u32, y: u32, w: u32, h: u32) {
    let center_x = x + w / 2;
    let center_y = y + h / 2;

    fill_rect(center_x - 150, center_y - 100, 300, 200, COLOR_CARD);
    fill_rect(center_x - 150, center_y - 100, 300, 2, COLOR_ACCENT);

    draw_string(center_x - 60, center_y - 70, b"N\xd8NOS Wallet", COLOR_ACCENT);
    draw_string(center_x - 70, center_y - 40, b"Wallet is locked", COLOR_TEXT_WHITE);
    draw_string(center_x - 70, center_y - 15, b"Enter master key:", COLOR_TEXT_DIM);

    let focused = PASSWORD_FOCUSED.load(Ordering::Relaxed);
    let field_color = if focused { COLOR_BORDER } else { COLOR_BG };
    fill_rect(center_x - 120, center_y + 5, 240, 28, field_color);
    fill_rect(center_x - 120, center_y + 5, 240, 1, if focused { COLOR_ACCENT } else { COLOR_BORDER });
    fill_rect(center_x - 120, center_y + 32, 240, 1, if focused { COLOR_ACCENT } else { COLOR_BORDER });

    let pwd_len = PASSWORD_LEN.load(Ordering::Relaxed);
    for i in 0..pwd_len.min(28) {
        fill_rect(center_x - 110 + (i as u32 * 8), center_y + 14, 4, 4, COLOR_TEXT_WHITE);
    }

    if focused {
        let cursor_x = center_x - 110 + (pwd_len.min(28) as u32 * 8);
        fill_rect(cursor_x, center_y + 10, 2, 14, COLOR_ACCENT);
    }

    fill_rect(center_x - 60, center_y + 50, 120, 32, COLOR_ACCENT);
    draw_string(center_x - 30, center_y + 60, b"Unlock", COLOR_BG);

    draw_string(center_x - 90, center_y + 90, b"Click field, type key", COLOR_TEXT_DIM);
}

fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, COLOR_SIDEBAR);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, COLOR_BORDER);

    draw_string(x + 16, y + 20, b"N\xd8NOS Wallet", COLOR_ACCENT);

    let current = get_view();
    let items: &[(&[u8], WalletView)] = &[
        (b"Overview", WalletView::Overview),
        (b"Send", WalletView::Send),
        (b"Receive", WalletView::Receive),
        (b"Transactions", WalletView::Transactions),
        (b"Stealth", WalletView::Stealth),
        (b"Settings", WalletView::Settings),
    ];

    for (i, (label, view)) in items.iter().enumerate() {
        let item_y = y + 60 + (i as u32) * 36;
        let is_selected = *view == current;

        if is_selected {
            fill_rect(x, item_y, SIDEBAR_WIDTH - 1, 32, 0xFF1F2937);
            fill_rect(x, item_y, 3, 32, COLOR_ACCENT);
        }

        let color = if is_selected { COLOR_TEXT_WHITE } else { COLOR_TEXT_DIM };
        draw_string(x + 20, item_y + 10, label, color);
    }

    let state = WALLET_STATE.lock();
    if let Some(account) = state.get_active_account() {
        let addr_hex = account.address_hex();
        let addr_short = truncate_address(&addr_hex);

        draw_string(x + 16, y + h - 60, b"Active:", COLOR_TEXT_DIM);
        draw_string(x + 16, y + h - 40, &addr_short, COLOR_TEXT_WHITE);
    }
}

fn draw_header(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, HEADER_HEIGHT, COLOR_BG);
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, COLOR_BORDER);

    let state = WALLET_STATE.lock();
    let total = state.total_balance();
    let (eth, wei) = {
        let wei_per_eth: u128 = 1_000_000_000_000_000_000;
        ((total / wei_per_eth) as u64, (total % wei_per_eth / 1_000_000_000_000_000) as u64)
    };

    draw_string(x + 20, y + 15, b"Total Balance", COLOR_TEXT_DIM);

    let mut balance_str = [0u8; 32];
    let len = format_balance(&mut balance_str, eth, wei);
    draw_string(x + 20, y + 35, &balance_str[..len], COLOR_TEXT_WHITE);
    draw_string(x + 20 + (len as u32 + 1) * 8, y + 35, b"ETH", COLOR_TEXT_DIM);
}

pub(super) fn format_balance(buf: &mut [u8; 32], eth: u64, decimals: u64) -> usize {
    let mut idx = 0;

    if eth == 0 {
        buf[idx] = b'0';
        idx += 1;
    } else {
        let mut n = eth;
        let mut digits = [0u8; 20];
        let mut digit_count = 0;
        while n > 0 {
            digits[digit_count] = (n % 10) as u8;
            n /= 10;
            digit_count += 1;
        }
        for i in (0..digit_count).rev() {
            buf[idx] = b'0' + digits[i];
            idx += 1;
        }
    }

    buf[idx] = b'.';
    idx += 1;

    let dec_digits = [
        ((decimals / 100) % 10) as u8,
        ((decimals / 10) % 10) as u8,
        (decimals % 10) as u8,
    ];

    for d in dec_digits {
        buf[idx] = b'0' + d;
        idx += 1;
    }

    idx
}

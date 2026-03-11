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

/*
 * Main wallet render coordinator.
 *
 * Handles the top-level drawing logic: locked/unlocked state detection,
 * sidebar navigation, header with total balance, and dispatching to the
 * appropriate view renderer based on current wallet state.
 *
 * Color scheme follows GitHub's dark mode palette for consistency.
 */

extern crate alloc;

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;

use super::state::*;
use super::types::truncate_address;
use super::render_views::{draw_overview, draw_send_view, draw_receive_view, draw_status_bar};
use super::render_transactions::draw_transactions_view;
use super::render_stealth::{draw_stealth_view, draw_settings_view};

pub(super) const COLOR_BG: u32 = 0xFF000000;
pub(super) const COLOR_SIDEBAR: u32 = 0xFF1C1C1E;
pub(super) const COLOR_CARD: u32 = 0xFF2C2C2E;
pub(super) const COLOR_BORDER: u32 = 0xFF38383A;
pub(super) const COLOR_TEXT_DIM: u32 = 0xFF8E8E93;
pub(super) const COLOR_TEXT_WHITE: u32 = 0xFFFFFFFF;
pub(super) const COLOR_ACCENT: u32 = 0xFF007AFF;
pub(super) const COLOR_GREEN: u32 = 0xFF34C759;
pub(super) const COLOR_YELLOW: u32 = 0xFFFFD60A;
pub(super) const COLOR_RED: u32 = 0xFFFF3B30;

const SIDEBAR_WIDTH: u32 = 200;
const HEADER_HEIGHT: u32 = 70;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);

    if !super::state::WALLET_INITIALIZED.load(Ordering::Relaxed) {
        super::state::WALLET_INITIALIZED.store(true, Ordering::Relaxed);
        auto_generate_wallet();
    }

    let unlocked = {
        let state = WALLET_STATE.lock();
        state.unlocked
    };

    if !unlocked {
        draw_locked_view(x, y, w, h);
        return;
    }

    let view = get_view();

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

    for gy in 0..h {
        let shade = ((gy as f32 / h as f32) * 30.0) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }

    draw_rounded_card(center_x - 160, center_y - 120, 320, 260, 0xFF2C2C2E);

    draw_lock_icon(center_x - 24, center_y - 100);

    draw_string(center_x - 60, center_y - 55, b"N\xd8NOS Wallet", COLOR_ACCENT);
    draw_string(center_x - 56, center_y - 30, b"Enter Password", COLOR_TEXT_WHITE);

    let focused = PASSWORD_FOCUSED.load(Ordering::Relaxed);
    draw_password_field(center_x - 130, center_y, 260, focused);

    let pwd_len = PASSWORD_LEN.load(Ordering::Relaxed);
    for i in 0..pwd_len.min(30) {
        fill_rect(center_x - 118 + (i as u32 * 8), center_y + 13, 6, 6, COLOR_TEXT_WHITE);
    }

    if focused {
        let cursor_x = center_x - 118 + (pwd_len.min(30) as u32 * 8);
        fill_rect(cursor_x, center_y + 8, 2, 16, COLOR_ACCENT);
    }

    draw_rounded_button(center_x - 130, center_y + 55, 125, 44, COLOR_ACCENT);
    draw_string(center_x - 108, center_y + 68, b"Unlock", COLOR_BG);

    draw_rounded_button(center_x + 5, center_y + 55, 125, 44, COLOR_GREEN);
    draw_string(center_x + 20, center_y + 68, b"New Wallet", COLOR_BG);
}

fn draw_rounded_card(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 16u32;
    for shadow in 0..8u32 {
        let alpha = 40 - shadow * 4;
        fill_rect(x + r + shadow, y + shadow + 4, w - 2 * r, h, (alpha << 24) | 0x000000);
    }
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + w - r + dx - 1, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + h - r + dy - 1, color);
        crate::graphics::framebuffer::put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
    }}}
}

fn draw_lock_icon(x: u32, y: u32) {
    fill_rect(x + 8, y, 32, 24, 0xFF3A3A3C);
    fill_rect(x + 4, y + 20, 40, 28, COLOR_ACCENT);
    fill_rect(x + 20, y + 28, 8, 12, 0xFF005BBB);
}

fn draw_password_field(x: u32, y: u32, w: u32, focused: bool) {
    let r = 10u32;
    let border = if focused { COLOR_ACCENT } else { COLOR_BORDER };
    fill_rect(x + r, y - 1, w - 2 * r, 34, border);
    fill_rect(x - 1, y + r - 1, w + 2, 32 - 2 * r + 2, border);
    let bg = 0xFF1C1C1E;
    fill_rect(x + r, y, w - 2 * r, 32, bg);
    fill_rect(x, y + r, w, 32 - 2 * r, bg);
}

fn draw_rounded_button(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 10u32;
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + w - r + dx - 1, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + h - r + dy - 1, color);
        crate::graphics::framebuffer::put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
    }}}
}

fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, COLOR_SIDEBAR);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, COLOR_BORDER);

    draw_string(x + 20, y + 24, b"N\xd8NOS", COLOR_ACCENT);
    draw_string(x + 68, y + 24, b"Wallet", COLOR_TEXT_WHITE);

    let current = get_view();
    let items: &[(&[u8], WalletView, u32)] = &[
        (b"Overview", WalletView::Overview, 0xFF007AFF),
        (b"Send", WalletView::Send, 0xFFFF9500),
        (b"Receive", WalletView::Receive, 0xFF34C759),
        (b"History", WalletView::Transactions, 0xFF5856D6),
        (b"Stealth", WalletView::Stealth, 0xFFBF5AF2),
        (b"Settings", WalletView::Settings, 0xFF8E8E93),
    ];

    for (i, (label, view, icon_color)) in items.iter().enumerate() {
        let item_y = y + 70 + (i as u32) * 48;
        let is_selected = *view == current;

        if is_selected {
            draw_rounded_item(x + 12, item_y, SIDEBAR_WIDTH - 24, 40, 0xFF3A3A3C);
        }

        fill_rect(x + 20, item_y + 8, 24, 24, *icon_color);
        draw_icon_glyph(x + 20, item_y + 8, i);

        let color = if is_selected { COLOR_TEXT_WHITE } else { COLOR_TEXT_DIM };
        draw_string(x + 52, item_y + 14, label, color);
    }

    let addr_short = {
        let state = WALLET_STATE.lock();
        state.get_active_account().map(|a| truncate_address(&a.address_hex()))
    };

    if let Some(addr) = addr_short {
        fill_rect(x + 12, y + h - 80, SIDEBAR_WIDTH - 24, 60, 0xFF2C2C2E);
        draw_string(x + 20, y + h - 70, b"Active Account", COLOR_TEXT_DIM);
        draw_string(x + 20, y + h - 50, &addr, COLOR_TEXT_WHITE);
    }
}

fn draw_rounded_item(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 8u32;
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + w - r + dx - 1, y + r - dy, color);
        crate::graphics::framebuffer::put_pixel(x + r - dx, y + h - r + dy - 1, color);
        crate::graphics::framebuffer::put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
    }}}
}

fn draw_icon_glyph(x: u32, y: u32, idx: usize) {
    let glyphs: [&[u8]; 6] = [b"\x7f", b"\x1a", b"\x19", b"\x1d", b"\x0f", b"\x2a"];
    if idx < 6 {
        crate::graphics::font::draw_char(x + 8, y + 4, glyphs[idx][0], 0xFFFFFFFF);
    }
}

fn draw_header(x: u32, y: u32, w: u32) {
    for gy in 0..HEADER_HEIGHT {
        let shade = (gy / 5) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, COLOR_BORDER);

    let (eth, wei, nox, nox_frac) = {
        let state = WALLET_STATE.lock();
        let total_eth = state.total_balance();
        let total_nox = state.total_nox_balance();
        let wei_per: u128 = 1_000_000_000_000_000_000;
        (
            (total_eth / wei_per) as u64,
            (total_eth % wei_per / 1_000_000_000_000_000) as u64,
            (total_nox / wei_per) as u64,
            (total_nox % wei_per / 1_000_000_000_000_000) as u64,
        )
    };

    draw_string(x + 24, y + 16, b"Total Balance", COLOR_TEXT_DIM);

    let mut balance_str = [0u8; 32];
    let len = format_balance(&mut balance_str, eth, wei);

    for (i, &ch) in balance_str[..len].iter().enumerate() {
        crate::graphics::font::draw_char_scaled(x + 24 + (i as u32) * 16, y + 34, ch, COLOR_TEXT_WHITE, 2);
    }
    draw_string(x + 24 + (len as u32) * 16 + 8, y + 42, b"ETH", COLOR_ACCENT);

    let mut nox_str = [0u8; 32];
    let nox_len = format_balance(&mut nox_str, nox, nox_frac);
    let nox_x = x + 24 + (len as u32) * 16 + 50;
    draw_string(nox_x, y + 42, &nox_str[..nox_len], COLOR_TEXT_WHITE);
    draw_string(nox_x + (nox_len as u32) * 8 + 8, y + 42, b"NOX", 0xFFBF5AF2);

    fill_rect(x + w - 110, y + 20, 90, 32, 0xFF2C2C2E);
    draw_string(x + w - 100, y + 28, b"Refresh", COLOR_ACCENT);
}

fn auto_generate_wallet() {
    use crate::crypto::blake3_hash;
    use super::state::init_wallet;

    let mut entropy = [0u8; 64];

    crate::crypto::random_api::generate_wallet_entropy(&mut entropy);

    let master_key = blake3_hash(&entropy);

    for b in entropy.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    let _ = init_wallet(master_key);
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

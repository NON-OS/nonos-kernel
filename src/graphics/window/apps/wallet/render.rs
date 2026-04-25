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
use super::render_stealth::{draw_settings_view, draw_stealth_view};
use super::render_transactions::draw_transactions_view;
use super::render_views::{
    draw_overview, draw_receive_view, draw_send_view, draw_status_bar, draw_zksync_view,
};
use super::state::*;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub(super) const COLOR_BG: u32 = 0xFF0A0A0F;
pub(super) const COLOR_CARD: u32 = 0xFF18181F;
pub(super) const COLOR_CARD_ELEVATED: u32 = 0xFF1E1E28;
pub(super) const COLOR_BORDER: u32 = 0xFF2A2A35;
pub(super) const COLOR_TEXT_DIM: u32 = 0xFF6B6B7A;
pub(super) const COLOR_TEXT_SECONDARY: u32 = 0xFF9999AA;
pub(super) const COLOR_TEXT_WHITE: u32 = 0xFFF5F5F7;
pub(super) const COLOR_ACCENT: u32 = 0xFF6366F1;
pub(super) const COLOR_ACCENT_GLOW: u32 = 0xFF818CF8;
pub(super) const COLOR_GREEN: u32 = 0xFF10B981;
pub(super) const COLOR_GREEN_GLOW: u32 = 0xFF34D399;
pub(super) const COLOR_YELLOW: u32 = 0xFFF59E0B;
pub(super) const COLOR_RED: u32 = 0xFFEF4444;
pub(super) const COLOR_PURPLE: u32 = 0xFFA855F7;
pub(super) const COLOR_CYAN: u32 = 0xFF06B6D4;
pub(super) const SIDEBAR_WIDTH: u32 = 220;
pub(super) const HEADER_HEIGHT: u32 = 80;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    if !super::state::WALLET_INITIALIZED.load(Ordering::Relaxed) {
        super::state::WALLET_INITIALIZED.store(true, Ordering::Relaxed);
        super::render_header::auto_generate_wallet();
    }
    let unlocked = {
        let state = WALLET_STATE.lock();
        state.unlocked
    };
    if !unlocked {
        super::render_locked::draw_locked_view(x, y, w, h);
        return;
    }
    let view = get_view();
    super::render_sidebar::draw_sidebar(x, y, h);
    super::render_header::draw_header(x + SIDEBAR_WIDTH, y, w - SIDEBAR_WIDTH);
    let content_x = x + SIDEBAR_WIDTH;
    let content_y = y + HEADER_HEIGHT;
    let content_w = w - SIDEBAR_WIDTH;
    let content_h = h - HEADER_HEIGHT - 30;
    match view {
        WalletView::Overview => draw_overview(content_x, content_y, content_w, content_h),
        WalletView::Send => draw_send_view(content_x, content_y, content_w, content_h),
        WalletView::Receive => draw_receive_view(content_x, content_y, content_w, content_h),
        WalletView::Transactions => {
            draw_transactions_view(content_x, content_y, content_w, content_h)
        }
        WalletView::Settings => draw_settings_view(content_x, content_y, content_w, content_h),
        WalletView::Stealth => draw_stealth_view(content_x, content_y, content_w, content_h),
        WalletView::ZkSync => draw_zksync_view(content_x, content_y, content_w, content_h),
        WalletView::Staking => {
            super::staking::draw_staking_view(content_x, content_y, content_w, content_h)
        }
    }
    draw_status_bar(x + SIDEBAR_WIDTH, y + h - 30, w - SIDEBAR_WIDTH);
}

pub(super) fn format_balance(buf: &mut [u8; 32], eth: u64, decimals: u64) -> usize {
    let mut idx = 0;
    if eth == 0 {
        buf[idx] = b'0';
        idx += 1;
    } else {
        let mut n = eth;
        let mut digits = [0u8; 20];
        let mut dc = 0;
        while n > 0 {
            digits[dc] = (n % 10) as u8;
            n /= 10;
            dc += 1;
        }
        for i in (0..dc).rev() {
            buf[idx] = b'0' + digits[i];
            idx += 1;
        }
    }
    buf[idx] = b'.';
    idx += 1;
    let dec_digits =
        [((decimals / 100) % 10) as u8, ((decimals / 10) % 10) as u8, (decimals % 10) as u8];
    for d in dec_digits {
        buf[idx] = b'0' + d;
        idx += 1;
    }
    idx
}

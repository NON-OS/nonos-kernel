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
use crate::graphics::framebuffer::fill_rect;
use super::state::*;
use super::render_views::{draw_overview, draw_send_view, draw_receive_view, draw_status_bar, draw_zksync_view};
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
pub(super) const SIDEBAR_WIDTH: u32 = 200;
pub(super) const HEADER_HEIGHT: u32 = 70;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    if !super::state::WALLET_INITIALIZED.load(Ordering::Relaxed) {
        super::state::WALLET_INITIALIZED.store(true, Ordering::Relaxed);
        super::render_header::auto_generate_wallet();
    }
    let unlocked = { let state = WALLET_STATE.lock(); state.unlocked };
    if !unlocked { super::render_locked::draw_locked_view(x, y, w, h); return; }
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
        WalletView::Transactions => draw_transactions_view(content_x, content_y, content_w, content_h),
        WalletView::Settings => draw_settings_view(content_x, content_y, content_w, content_h),
        WalletView::Stealth => draw_stealth_view(content_x, content_y, content_w, content_h),
        WalletView::ZkSync => draw_zksync_view(content_x, content_y, content_w, content_h),
        WalletView::Staking => super::staking::draw_staking_view(content_x, content_y, content_w, content_h),
    }
    draw_status_bar(x + SIDEBAR_WIDTH, y + h - 30, w - SIDEBAR_WIDTH);
}

pub(super) fn format_balance(buf: &mut [u8; 32], eth: u64, decimals: u64) -> usize {
    let mut idx = 0;
    if eth == 0 { buf[idx] = b'0'; idx += 1; }
    else { let mut n = eth; let mut digits = [0u8; 20]; let mut dc = 0; while n > 0 { digits[dc] = (n % 10) as u8; n /= 10; dc += 1; } for i in (0..dc).rev() { buf[idx] = b'0' + digits[i]; idx += 1; } }
    buf[idx] = b'.'; idx += 1;
    let dec_digits = [((decimals / 100) % 10) as u8, ((decimals / 10) % 10) as u8, (decimals % 10) as u8];
    for d in dec_digits { buf[idx] = b'0' + d; idx += 1; }
    idx
}

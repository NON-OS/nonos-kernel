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

use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::draw_string;
use super::state::{get_view, WalletView, WALLET_STATE};
use super::types::truncate_address;
use super::render::{COLOR_SIDEBAR, COLOR_BORDER, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_TEXT_DIM, SIDEBAR_WIDTH};

pub(super) fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, COLOR_SIDEBAR);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, COLOR_BORDER);
    draw_string(x + 20, y + 24, b"N\xd8NOS", COLOR_ACCENT);
    draw_string(x + 68, y + 24, b"Wallet", COLOR_TEXT_WHITE);
    let current = get_view();
    let items: &[(&[u8], WalletView, u32)] = &[(b"Overview", WalletView::Overview, 0xFF007AFF), (b"Send", WalletView::Send, 0xFFFF9500), (b"Receive", WalletView::Receive, 0xFF34C759), (b"Staking", WalletView::Staking, 0xFFFFD60A), (b"ZkSync L2", WalletView::ZkSync, 0xFF8B5CF6), (b"History", WalletView::Transactions, 0xFF5856D6), (b"Stealth", WalletView::Stealth, 0xFFBF5AF2), (b"Settings", WalletView::Settings, 0xFF8E8E93)];
    for (i, (label, view, icon_color)) in items.iter().enumerate() {
        let item_y = y + 70 + (i as u32) * 48;
        if *view == current { draw_rounded_item(x + 12, item_y, SIDEBAR_WIDTH - 24, 40, 0xFF3A3A3C); }
        fill_rect(x + 20, item_y + 8, 24, 24, *icon_color);
        draw_icon_glyph(x + 20, item_y + 8, i);
        draw_string(x + 52, item_y + 14, label, if *view == current { COLOR_TEXT_WHITE } else { COLOR_TEXT_DIM });
    }
    let addr_short = { let state = WALLET_STATE.lock(); state.get_active_account().map(|a| truncate_address(&a.address_hex())) };
    if let Some(addr) = addr_short {
        fill_rect(x + 12, y + h - 80, SIDEBAR_WIDTH - 24, 60, 0xFF2C2C2E);
        draw_string(x + 20, y + h - 70, b"Active Account", COLOR_TEXT_DIM);
        draw_string(x + 20, y + h - 50, &addr, COLOR_TEXT_WHITE);
    }
}

fn draw_rounded_item(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 8u32;
    fill_rect(x + r, y, w - 2 * r, h, color); fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r { put_pixel(x + r - dx, y + r - dy, color); put_pixel(x + w - r + dx - 1, y + r - dy, color); put_pixel(x + r - dx, y + h - r + dy - 1, color); put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color); }}}
}

fn draw_icon_glyph(x: u32, y: u32, idx: usize) {
    let glyphs: [&[u8]; 8] = [b"\x7f", b"\x1a", b"\x19", b"\x24", b"\x1d", b"\x0f", b"\x2a", b"\x2e"];
    if idx < 8 { crate::graphics::font::draw_char(x + 8, y + 4, glyphs[idx][0], 0xFFFFFFFF); }
}

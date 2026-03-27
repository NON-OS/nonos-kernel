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

use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use super::state::{get_view, WalletView, WALLET_STATE};
use super::types::truncate_address;
use super::render::{COLOR_BORDER, COLOR_SIDEBAR_HOVER, COLOR_CARD, COLOR_TEXT_DIM, COLOR_TEXT_SECONDARY, COLOR_TEXT_WHITE, COLOR_ACCENT, COLOR_GREEN, SIDEBAR_WIDTH};

pub(super) fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, 0xFF121218);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, COLOR_BORDER);
    draw_string(x + 24, y + 28, b"N\xd8NOS", COLOR_ACCENT);
    draw_string(x + 76, y + 28, b"Wallet", COLOR_TEXT_WHITE);
    let current = get_view();
    let items: &[(&[u8], WalletView)] = &[
        (b"Overview", WalletView::Overview),
        (b"Send", WalletView::Send),
        (b"Receive", WalletView::Receive),
        (b"Staking", WalletView::Staking),
        (b"ZkSync L2", WalletView::ZkSync),
        (b"History", WalletView::Transactions),
    ];
    for (i, (label, view)) in items.iter().enumerate() {
        let item_y = y + 70 + (i as u32) * 50;
        if *view == current {
            fill_rect(x + 12, item_y, SIDEBAR_WIDTH - 24, 40, COLOR_SIDEBAR_HOVER);
            fill_rect(x, item_y + 8, 3, 24, COLOR_ACCENT);
        }
        draw_string(x + 24, item_y + 14, label, if *view == current { COLOR_TEXT_WHITE } else { COLOR_TEXT_SECONDARY });
    }
    draw_account_info(x, y, h);
}


fn draw_account_info(x: u32, y: u32, h: u32) {
    let card_y = y + h - 90;
    fill_rect(x + 12, card_y, SIDEBAR_WIDTH - 24, 75, COLOR_CARD);
    fill_rect(x + 12, card_y, SIDEBAR_WIDTH - 24, 1, COLOR_BORDER);
    let addr = { let state = WALLET_STATE.lock(); state.get_active_account().map(|a| truncate_address(&a.address_hex())) };
    if let Some(addr_short) = addr {
        draw_string(x + 24, card_y + 14, b"Active Account", COLOR_TEXT_DIM);
        fill_rect(x + 24, card_y + 35, 8, 8, COLOR_GREEN);
        draw_string(x + 38, card_y + 33, b"Connected", COLOR_GREEN);
        draw_string(x + 24, card_y + 52, &addr_short, COLOR_TEXT_WHITE);
    }
}

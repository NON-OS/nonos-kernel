// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::render::{
    COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT_DIM, COLOR_TEXT_SECONDARY, COLOR_TEXT_WHITE,
    SIDEBAR_WIDTH,
};
use super::state::{get_view, WalletView, WALLET_STATE};
use super::types::truncate_address;
use crate::graphics::framebuffer::{fill_rect, rounded_rect_blend};
use crate::graphics::window::draw_string;

const SIDEBAR_BG: u32 = 0xFF0D0D12;
const ITEM_ACTIVE_BG: u32 = 0x20FFFFFF;
const ACCENT_INDICATOR: u32 = 0xFF6366F1;

pub(super) fn draw_sidebar(x: u32, y: u32, h: u32) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, SIDEBAR_BG);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, 0x20FFFFFF);
    draw_brand_header(x, y);
    draw_menu_items(x, y);
    draw_account_card(x, y, h);
}

fn draw_brand_header(x: u32, y: u32) {
    rounded_rect_blend(x + 16, y + 16, 40, 40, 10, 0x30FFFFFF);
    draw_string(x + 26, y + 28, b"\xd8", COLOR_ACCENT);
    draw_string(x + 68, y + 20, b"NONOS", COLOR_TEXT_WHITE);
    draw_string(x + 68, y + 36, b"Wallet", COLOR_TEXT_DIM);
}

fn draw_menu_items(x: u32, y: u32) {
    let current = get_view();
    let items: [(&[u8], WalletView, &[u8]); 6] = [
        (b"Overview", WalletView::Overview, b"\x01"),
        (b"Send", WalletView::Send, b"\x02"),
        (b"Receive", WalletView::Receive, b"\x03"),
        (b"Staking", WalletView::Staking, b"\x04"),
        (b"ZkSync L2", WalletView::ZkSync, b"\x05"),
        (b"History", WalletView::Transactions, b"\x06"),
    ];
    for (i, (label, view, _icon)) in items.iter().enumerate() {
        let item_y = y + 80 + (i as u32) * 44;
        let is_active = *view == current;
        if is_active {
            rounded_rect_blend(x + 12, item_y, SIDEBAR_WIDTH - 24, 36, 8, ITEM_ACTIVE_BG);
            fill_rect(x + 4, item_y + 8, 3, 20, ACCENT_INDICATOR);
        }
        let text_color = if is_active { COLOR_TEXT_WHITE } else { COLOR_TEXT_SECONDARY };
        draw_string(x + 28, item_y + 12, label, text_color);
    }
}

fn draw_account_card(x: u32, y: u32, h: u32) {
    let card_y = y + h - 100;
    rounded_rect_blend(x + 12, card_y, SIDEBAR_WIDTH - 24, 85, 12, 0x15FFFFFF);
    fill_rect(x + 12, card_y, SIDEBAR_WIDTH - 24, 1, 0x10FFFFFF);
    let addr = {
        let state = WALLET_STATE.lock();
        state.get_active_account().map(|a| truncate_address(&a.address_hex()))
    };
    if let Some(addr_short) = addr {
        draw_string(x + 24, card_y + 16, b"Active Account", COLOR_TEXT_DIM);
        rounded_rect_blend(x + 24, card_y + 36, 10, 10, 5, COLOR_GREEN);
        draw_string(x + 40, card_y + 35, b"Connected", COLOR_GREEN);
        draw_string(x + 24, card_y + 56, &addr_short, COLOR_TEXT_WHITE);
    } else {
        draw_string(x + 24, card_y + 16, b"No Account", COLOR_TEXT_DIM);
        draw_string(x + 24, card_y + 40, b"Create or import", COLOR_TEXT_SECONDARY);
    }
    draw_string(x + 24, y + h - 8, b"Wallet unlocked", COLOR_GREEN);
}

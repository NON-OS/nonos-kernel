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

use super::render::{
    format_balance, COLOR_ACCENT, COLOR_BORDER, COLOR_GREEN, COLOR_TEXT_DIM, COLOR_TEXT_WHITE,
    HEADER_HEIGHT,
};
use super::state::WALLET_STATE;
use crate::graphics::framebuffer::{fill_rect, rounded_rect_blend};
use crate::graphics::window::draw_string;

pub(super) fn draw_header(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, HEADER_HEIGHT, 0xFF0D0D12);
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, COLOR_BORDER);
    draw_balance_section(x, y);
    draw_action_buttons(x, y, w);
}

fn draw_balance_section(x: u32, y: u32) {
    let (eth, wei, nox, nox_frac) = get_balances();
    draw_string(x + 24, y + 12, b"Total Balance", COLOR_TEXT_DIM);
    let mut buf = [0u8; 32];
    let len = format_balance(&mut buf, eth, wei);
    for (i, &ch) in buf[..len].iter().enumerate() {
        crate::graphics::font::draw_char_scaled(
            x + 24 + (i as u32) * 16,
            y + 28,
            ch,
            COLOR_TEXT_WHITE,
            2,
        );
    }
    draw_string(x + 24 + (len as u32) * 16 + 8, y + 36, b"ETH", COLOR_ACCENT);
    let mut nox_buf = [0u8; 32];
    let nox_len = format_balance(&mut nox_buf, nox, nox_frac);
    let nox_x = x + 24 + (len as u32) * 16 + 60;
    draw_string(nox_x, y + 36, &nox_buf[..nox_len], COLOR_TEXT_WHITE);
    draw_string(nox_x + (nox_len as u32) * 8 + 8, y + 36, b"NOX", 0xFFBF5AF2);
}

fn get_balances() -> (u64, u64, u64, u64) {
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
}

fn draw_action_buttons(x: u32, y: u32, w: u32) {
    rounded_rect_blend(x + w - 180, y + 20, 70, 32, 8, 0x20FFFFFF);
    draw_string(x + w - 168, y + 28, b"Refresh", COLOR_ACCENT);
    rounded_rect_blend(x + w - 100, y + 20, 80, 32, 8, COLOR_GREEN);
    draw_string(x + w - 88, y + 28, b"Connect", 0xFF0A0A0F);
}

pub(super) fn auto_generate_wallet() {
    use super::state::init_wallet;
    use crate::crypto::blake3_hash;
    let mut entropy = [0u8; 64];
    crate::crypto::random_api::generate_wallet_entropy(&mut entropy);
    let master_key = blake3_hash(&entropy);
    for b in entropy.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    let _ = init_wallet(master_key);
}

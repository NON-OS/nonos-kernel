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
use super::state::WALLET_STATE;
use super::render::{format_balance, COLOR_BORDER, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_ACCENT, HEADER_HEIGHT};

pub(super) fn draw_header(x: u32, y: u32, w: u32) {
    for gy in 0..HEADER_HEIGHT { let s = (gy / 5) as u8; fill_rect(x, y + gy, w, 1, 0xFF000000 | ((s as u32) << 16) | ((s as u32) << 8) | (s as u32)); }
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, COLOR_BORDER);
    let (eth, wei, nox, nox_frac) = {
        let state = WALLET_STATE.lock();
        let total_eth = state.total_balance();
        let total_nox = state.total_nox_balance();
        let wei_per: u128 = 1_000_000_000_000_000_000;
        ((total_eth / wei_per) as u64, (total_eth % wei_per / 1_000_000_000_000_000) as u64, (total_nox / wei_per) as u64, (total_nox % wei_per / 1_000_000_000_000_000) as u64)
    };
    draw_string(x + 24, y + 16, b"Total Balance", COLOR_TEXT_DIM);
    let mut balance_str = [0u8; 32];
    let len = format_balance(&mut balance_str, eth, wei);
    for (i, &ch) in balance_str[..len].iter().enumerate() { crate::graphics::font::draw_char_scaled(x + 24 + (i as u32) * 16, y + 34, ch, COLOR_TEXT_WHITE, 2); }
    draw_string(x + 24 + (len as u32) * 16 + 8, y + 42, b"ETH", COLOR_ACCENT);
    let mut nox_str = [0u8; 32];
    let nox_len = format_balance(&mut nox_str, nox, nox_frac);
    let nox_x = x + 24 + (len as u32) * 16 + 50;
    draw_string(nox_x, y + 42, &nox_str[..nox_len], COLOR_TEXT_WHITE);
    draw_string(nox_x + (nox_len as u32) * 8 + 8, y + 42, b"NOX", 0xFFBF5AF2);
    fill_rect(x + w - 110, y + 20, 90, 32, 0xFF2C2C2E);
    draw_string(x + w - 100, y + 28, b"Refresh", COLOR_ACCENT);
}

pub(super) fn auto_generate_wallet() {
    use crate::crypto::blake3_hash;
    use super::state::init_wallet;
    let mut entropy = [0u8; 64];
    crate::crypto::random_api::generate_wallet_entropy(&mut entropy);
    let master_key = blake3_hash(&entropy);
    for b in entropy.iter_mut() { unsafe { core::ptr::write_volatile(b, 0) }; }
    let _ = init_wallet(master_key);
}

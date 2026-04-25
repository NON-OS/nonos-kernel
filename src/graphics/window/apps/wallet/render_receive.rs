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

use super::render::{COLOR_BG, COLOR_CARD, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use super::render_views::draw_rounded_rect;
use super::state::WALLET_STATE;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;

pub(super) fn draw_receive_view(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_string(x + 20, y + 20, b"Receive Funds", COLOR_TEXT_WHITE);
    let addr_hex = {
        let state = WALLET_STATE.lock();
        state.get_active_account().map(|a| a.address_hex())
    };
    if let Some(addr_hex) = addr_hex {
        for shadow in 0..4u32 {
            draw_rounded_rect(
                x + 20 + shadow / 2,
                y + 50 + shadow + 2,
                w - 40,
                240,
                14,
                ((15 - shadow * 3) << 24) | 0x000000,
            );
        }
        draw_rounded_rect(x + 20, y + 50, w - 40, 240, 14, COLOR_CARD);
        draw_string(x + 36, y + 70, b"Your Wallet Address", COLOR_TEXT_DIM);
        draw_rounded_rect(x + w / 2 - 87, y + 90, 174, 174, 12, 0xFFFFFFFF);
        if let Some(qr) = crate::graphics::qrcode::encode_qr(&addr_hex) {
            crate::graphics::qrcode::draw_qr(
                &qr,
                x + w / 2 - 82,
                y + 95,
                5,
                0xFF000000,
                0xFFFFFFFF,
            );
        }
        draw_rounded_rect(x + 36, y + 275, w - 72, 36, 8, 0xFF1C1C1E);
        let addr_start = (w - 72 - (addr_hex.len() as u32 * 8)) / 2;
        draw_string(x + 36 + addr_start, y + 285, &addr_hex, 0xFF34C759);
        draw_string(x + w / 2 - 120, y + 320, b"Scan QR code or copy address", COLOR_TEXT_DIM);
    }
}

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
    format_balance, COLOR_ACCENT, COLOR_BG, COLOR_BORDER, COLOR_CARD, COLOR_TEXT_DIM,
    COLOR_TEXT_WHITE,
};
use super::render_views::draw_rounded_rect;
use super::state::{
    INPUT_CURSOR, INPUT_FOCUSED, SEND_ADDRESS, SEND_ADDRESS_LEN, SEND_AMOUNT, SEND_AMOUNT_LEN,
    SEND_FIELD, SEND_TOKEN_TYPE,
};
use super::types::TokenType;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use core::sync::atomic::Ordering;

pub(super) fn draw_send_view(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_string(x + 20, y + 20, b"Send Transaction", COLOR_TEXT_WHITE);
    for shadow in 0..4u32 {
        draw_rounded_rect(
            x + 20 + shadow / 2,
            y + 50 + shadow + 2,
            w - 40,
            230,
            14,
            ((15 - shadow * 3) << 24) | 0x000000,
        );
    }
    draw_rounded_rect(x + 20, y + 50, w - 40, 230, 14, COLOR_CARD);
    draw_string(x + 36, y + 70, b"Recipient Address", COLOR_TEXT_DIM);
    let field = SEND_FIELD.load(Ordering::SeqCst);
    let addr_focused = field == 0 && INPUT_FOCUSED.load(Ordering::SeqCst);
    draw_input_field(x + 36, y + 90, w - 72, 32, addr_focused);
    let send_addr = SEND_ADDRESS.lock();
    let addr_len = SEND_ADDRESS_LEN.load(Ordering::SeqCst);
    for (i, &ch) in send_addr[..addr_len].iter().enumerate() {
        if i < 50 {
            draw_char(x + 48 + (i as u32) * 8, y + 98, ch, COLOR_TEXT_WHITE);
        }
    }
    if addr_focused {
        let cursor = INPUT_CURSOR.load(Ordering::SeqCst).min(addr_len);
        fill_rect(x + 48 + (cursor as u32) * 8, y + 96, 2, 20, COLOR_ACCENT);
    }
    drop(send_addr);
    draw_string(x + 36, y + 135, b"Amount", COLOR_TEXT_DIM);
    let amount_focused = field == 1 && INPUT_FOCUSED.load(Ordering::SeqCst);
    draw_input_field(x + 36, y + 155, w - 120, 32, amount_focused);
    let send_amount = SEND_AMOUNT.lock();
    let amount_len = SEND_AMOUNT_LEN.load(Ordering::SeqCst);
    for (i, &ch) in send_amount[..amount_len].iter().enumerate() {
        draw_char(x + 48 + (i as u32) * 8, y + 163, ch, COLOR_TEXT_WHITE);
    }
    if amount_focused {
        let cursor = INPUT_CURSOR.load(Ordering::SeqCst).min(amount_len);
        fill_rect(x + 48 + (cursor as u32) * 8, y + 161, 2, 20, COLOR_ACCENT);
    }
    drop(send_amount);
    let token_type = match SEND_TOKEN_TYPE.load(Ordering::SeqCst) {
        0 => TokenType::Eth,
        _ => TokenType::Nox,
    };
    let token_color = match token_type {
        TokenType::Eth => 0xFF34C759,
        TokenType::Nox => 0xFFBF5AF2,
    };
    draw_rounded_rect(x + w - 80, y + 155, 44, 32, 8, token_color);
    draw_string(x + w - 70, y + 163, token_type.symbol(), 0xFF000000);
    draw_string(x + 36, y + 200, b"Network Fee", COLOR_TEXT_DIM);
    draw_rounded_rect(x + 36, y + 218, w - 72, 28, 6, 0xFF1A1A2E);
    let gas_wei = 21000u64 * 20 * 1_000_000_000;
    let mut gas_str = [0u8; 32];
    let len = format_balance(
        &mut gas_str,
        gas_wei / 1_000_000_000_000_000_000,
        (gas_wei % 1_000_000_000_000_000_000) / 1_000_000_000_000_000,
    );
    draw_string(x + 48, y + 224, &gas_str[..len], COLOR_TEXT_WHITE);
    draw_string(x + 48 + (len as u32 + 1) * 8, y + 224, b"ETH", COLOR_TEXT_DIM);
    draw_string(x + w - 120, y + 224, b"(20 Gwei)", COLOR_TEXT_DIM);
    draw_rounded_rect(x + w / 2 - 65, y + 295, 130, 40, 10, COLOR_ACCENT);
    for gy in 0..4u32 {
        fill_rect(x + w / 2 - 55, y + 296 + gy, 110, 1, ((20 - gy * 5) << 24) | 0xFFFFFF);
    }
    draw_string(x + w / 2 - 20, y + 307, b"Send", 0xFF000000);
}

fn draw_input_field(x: u32, y: u32, w: u32, h: u32, focused: bool) {
    let border_color = if focused { COLOR_ACCENT } else { COLOR_BORDER };
    draw_rounded_rect(x - 1, y - 1, w + 2, h + 2, 8, border_color);
    draw_rounded_rect(x, y, w, h, 7, 0xFF1C1C1E);
}

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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use crate::graphics::window::draw_string;

use super::state::*;
use super::state_ops::get_block_number;
use super::types::truncate_address;
use super::render::{
    format_balance, COLOR_BORDER, COLOR_CARD, COLOR_TEXT_DIM,
};

fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r {
        for dx in 0..r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(x + r - dx, y + r - dy, color);
                put_pixel(x + w - r + dx - 1, y + r - dy, color);
                put_pixel(x + r - dx, y + h - r + dy - 1, color);
                put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
            }
        }
    }
}

fn draw_input_field(x: u32, y: u32, w: u32, h: u32, focused: bool) {
    let border_color = if focused { COLOR_ACCENT } else { COLOR_BORDER };
    draw_rounded_rect(x - 1, y - 1, w + 2, h + 2, 8, border_color);
    draw_rounded_rect(x, y, w, h, 7, 0xFF1C1C1E);
}

pub(super) fn draw_overview(x: u32, y: u32, w: u32, h: u32) {
    draw_string(x + 20, y + 20, b"Accounts", COLOR_TEXT_WHITE);

    /* add account button */
    draw_rounded_rect(x + w - 190, y + 15, 80, 32, 8, 0xFF34C759);
    draw_string(x + w - 165, y + 23, b"+ New", 0xFF000000);

    draw_rounded_rect(x + w - 100, y + 15, 80, 32, 8, COLOR_ACCENT);
    draw_string(x + w - 90, y + 23, b"Refresh", 0xFF000000);

    let state = WALLET_STATE.lock();
    for (i, account) in state.accounts.iter().enumerate() {
        let card_y = y + 55 + (i as u32) * 85;
        if card_y + 75 > y + h {
            break;
        }

        for shadow in 0..4u32 {
            let alpha = 15 - shadow * 3;
            draw_rounded_rect(x + 20 + shadow / 2, card_y + shadow + 2, w - 40, 75, 12, (alpha << 24) | 0x000000);
        }

        draw_rounded_rect(x + 20, card_y, w - 40, 75, 12, COLOR_CARD);

        fill_rect(x + 32, card_y + 12, 28, 28, 0xFF3A3A3C);
        let mut idx_str = [0u8; 4];
        idx_str[0] = b'#';
        let idx_len = format_u32(&mut idx_str[1..], account.index);
        draw_string(x + 36, card_y + 18, &idx_str[..1 + idx_len], COLOR_TEXT_WHITE);

        draw_string(x + 68, card_y + 14, &account.name[..account.name_len], COLOR_TEXT_WHITE);

        let addr_hex = account.address_hex();
        let addr_short = truncate_address(&addr_hex);
        draw_string(x + 68, card_y + 32, &addr_short, COLOR_TEXT_DIM);

        let (eth, wei) = account.balance_eth();
        let mut balance_str = [0u8; 32];
        let len = format_balance(&mut balance_str, eth, wei / 1_000_000_000_000_000);
        draw_string(x + w - 140, card_y + 22, &balance_str[..len], COLOR_TEXT_WHITE);
        draw_string(x + w - 140 + (len as u32 + 1) * 8, card_y + 22, b"ETH", 0xFF34C759);
    }
}

fn format_u32(buf: &mut [u8], n: u32) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut val = n;
    let mut digits = [0u8; 10];
    let mut digit_count = 0;
    while val > 0 {
        digits[digit_count] = (val % 10) as u8;
        val /= 10;
        digit_count += 1;
    }
    for i in (0..digit_count).rev() {
        buf[digit_count - 1 - i] = b'0' + digits[i];
    }
    digit_count
}

pub(super) fn draw_send_view(x: u32, y: u32, w: u32, _h: u32) {
    draw_string(x + 20, y + 20, b"Send Transaction", COLOR_TEXT_WHITE);

    for shadow in 0..4u32 {
        let alpha = 15 - shadow * 3;
        draw_rounded_rect(x + 20 + shadow / 2, y + 50 + shadow + 2, w - 40, 230, 14, (alpha << 24) | 0x000000);
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

    draw_rounded_rect(x + w - 80, y + 155, 44, 32, 8, 0xFF3A3A3C);
    draw_string(x + w - 70, y + 163, b"ETH", 0xFF34C759);

    draw_string(x + 36, y + 200, b"Network Fee", COLOR_TEXT_DIM);
    draw_rounded_rect(x + 36, y + 218, w - 72, 28, 6, 0xFF1A1A2E);

    let gas_limit: u64 = 21000;
    let gas_price_gwei: u64 = 20;
    let total_gas_wei = gas_limit * gas_price_gwei * 1_000_000_000;
    let gas_eth = total_gas_wei / 1_000_000_000_000_000_000;
    let gas_remainder = (total_gas_wei % 1_000_000_000_000_000_000) / 1_000_000_000_000_000;

    let mut gas_str = [0u8; 32];
    let len = format_balance(&mut gas_str, gas_eth, gas_remainder);
    draw_string(x + 48, y + 224, &gas_str[..len], COLOR_TEXT_WHITE);
    draw_string(x + 48 + (len as u32 + 1) * 8, y + 224, b"ETH", COLOR_TEXT_DIM);

    let mut gwei_str = [0u8; 16];
    gwei_str[0] = b'(';
    let gwei_len = format_u64(&mut gwei_str[1..], gas_price_gwei);
    gwei_str[1 + gwei_len] = b' ';
    gwei_str[2 + gwei_len] = b'G';
    gwei_str[3 + gwei_len] = b'w';
    gwei_str[4 + gwei_len] = b'e';
    gwei_str[5 + gwei_len] = b'i';
    gwei_str[6 + gwei_len] = b')';
    draw_string(x + w - 120, y + 224, &gwei_str[..7 + gwei_len], COLOR_TEXT_DIM);

    draw_rounded_rect(x + w / 2 - 65, y + 295, 130, 40, 10, COLOR_ACCENT);
    for gy in 0..4u32 {
        let alpha = 20 - gy * 5;
        fill_rect(x + w / 2 - 55, y + 296 + gy, 110, 1, (alpha << 24) | 0xFFFFFF);
    }
    draw_string(x + w / 2 - 20, y + 307, b"Send", 0xFF000000);
}

fn format_u64(buf: &mut [u8], n: u64) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut val = n;
    let mut digits = [0u8; 20];
    let mut digit_count = 0;
    while val > 0 {
        digits[digit_count] = (val % 10) as u8;
        val /= 10;
        digit_count += 1;
    }
    for i in (0..digit_count).rev() {
        buf[digit_count - 1 - i] = b'0' + digits[i];
    }
    digit_count
}

pub(super) fn draw_receive_view(x: u32, y: u32, w: u32, _h: u32) {
    draw_string(x + 20, y + 20, b"Receive Funds", COLOR_TEXT_WHITE);

    let state = WALLET_STATE.lock();
    if let Some(account) = state.get_active_account() {
        for shadow in 0..4u32 {
            let alpha = 15 - shadow * 3;
            draw_rounded_rect(x + 20 + shadow / 2, y + 50 + shadow + 2, w - 40, 240, 14, (alpha << 24) | 0x000000);
        }
        draw_rounded_rect(x + 20, y + 50, w - 40, 240, 14, COLOR_CARD);

        draw_string(x + 36, y + 70, b"Your Wallet Address", COLOR_TEXT_DIM);

        let addr_hex = account.address_hex();

        draw_rounded_rect(x + w / 2 - 87, y + 90, 174, 174, 12, 0xFFFFFFFF);

        if let Some(qr) = crate::graphics::qrcode::encode_qr(&addr_hex) {
            crate::graphics::qrcode::draw_qr(&qr, x + w / 2 - 82, y + 95, 5, 0xFF000000, 0xFFFFFFFF);
        }

        draw_rounded_rect(x + 36, y + 275, w - 72, 36, 8, 0xFF1C1C1E);
        let addr_start = (w - 72 - (addr_hex.len() as u32 * 8)) / 2;
        draw_string(x + 36 + addr_start, y + 285, &addr_hex, 0xFF34C759);

        draw_string(x + w / 2 - 120, y + 320, b"Scan QR code or copy address", COLOR_TEXT_DIM);
    }
}

pub(super) fn draw_status_bar(x: u32, y: u32, w: u32) {
    use super::render::{COLOR_GREEN, COLOR_RED};

    for gy in 0..32u32 {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y, w, 1, COLOR_BORDER);

    let status = STATUS_MSG.lock();
    let status_len = STATUS_LEN.load(Ordering::SeqCst);
    let success = STATUS_SUCCESS.load(Ordering::SeqCst);

    if status_len > 0 {
        let color = if success { COLOR_GREEN } else { COLOR_RED };
        fill_rect(x + 16, y + 10, 8, 8, color);
        draw_string(x + 30, y + 9, &status[..status_len], COLOR_TEXT_WHITE);
    }

    if let Some(block_num) = get_block_number() {
        let mut block_str = [0u8; 24];
        block_str[0] = b'B';
        block_str[1] = b'l';
        block_str[2] = b'o';
        block_str[3] = b'c';
        block_str[4] = b'k';
        block_str[5] = b':';
        block_str[6] = b' ';
        let len = format_u64(&mut block_str[7..], block_num);
        draw_string(x + w - 150, y + 9, &block_str[..7 + len], COLOR_TEXT_DIM);
    }
}

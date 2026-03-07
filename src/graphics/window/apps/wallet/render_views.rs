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

/*
 * Main wallet view rendering functions.
 *
 * This module handles rendering the primary wallet views:
 * - Overview: Shows all accounts with balances and a refresh button
 * - Send: Transaction form with address input, amount, and gas estimate
 * - Receive: QR code display for the active account's address
 * - Status bar: Shows operation results and current block number
 *
 * For transactions view, see render_transactions.rs.
 */

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use crate::graphics::window::draw_string;

use super::state::*;
use super::state_ops::get_block_number;
use super::types::truncate_address;
use super::render::{
    format_balance, COLOR_BG, COLOR_BORDER, COLOR_CARD, COLOR_SIDEBAR,
    COLOR_TEXT_DIM,
};

pub(super) fn draw_overview(x: u32, y: u32, w: u32, h: u32) {
    draw_string(x + 20, y + 20, b"Accounts", COLOR_TEXT_WHITE);

    fill_rect(x + w - 100, y + 15, 80, 28, COLOR_ACCENT);
    draw_string(x + w - 90, y + 21, b"Refresh", 0xFF0D1117);

    let state = WALLET_STATE.lock();
    for (i, account) in state.accounts.iter().enumerate() {
        let card_y = y + 50 + (i as u32) * 80;
        if card_y + 70 > y + h {
            break;
        }

        fill_rect(x + 20, card_y, w - 40, 70, COLOR_CARD);
        fill_rect(x + 20, card_y, w - 40, 1, COLOR_BORDER);

        let mut idx_str = [0u8; 4];
        idx_str[0] = b'#';
        let idx_len = format_u32(&mut idx_str[1..], account.index);
        draw_string(x + 36, card_y + 12, &idx_str[..1 + idx_len], COLOR_TEXT_DIM);

        draw_string(x + 60, card_y + 12, &account.name[..account.name_len], COLOR_TEXT_WHITE);

        let addr_hex = account.address_hex();
        let addr_short = truncate_address(&addr_hex);
        draw_string(x + 36, card_y + 30, &addr_short, COLOR_TEXT_DIM);

        let (eth, wei) = account.balance_eth();
        let mut balance_str = [0u8; 32];
        let len = format_balance(&mut balance_str, eth, wei / 1_000_000_000_000_000);
        draw_string(x + w - 140, card_y + 20, &balance_str[..len], COLOR_TEXT_WHITE);
        draw_string(x + w - 140 + (len as u32 + 1) * 8, card_y + 20, b"ETH", COLOR_TEXT_DIM);
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
    draw_string(x + 20, y + 20, b"Send", COLOR_TEXT_WHITE);

    fill_rect(x + 20, y + 50, w - 40, 220, COLOR_CARD);

    draw_string(x + 36, y + 70, b"To Address", COLOR_TEXT_DIM);
    fill_rect(x + 36, y + 90, w - 72, 28, COLOR_BG);
    fill_rect(x + 36, y + 90, w - 72, 1, COLOR_BORDER);

    let send_addr = SEND_ADDRESS.lock();
    let addr_len = SEND_ADDRESS_LEN.load(Ordering::SeqCst);
    let field = SEND_FIELD.load(Ordering::SeqCst);

    for (i, &ch) in send_addr[..addr_len].iter().enumerate() {
        if i < 50 {
            draw_char(x + 44 + (i as u32) * 8, y + 96, ch, COLOR_TEXT_WHITE);
        }
    }

    if field == 0 && INPUT_FOCUSED.load(Ordering::SeqCst) {
        let cursor = INPUT_CURSOR.load(Ordering::SeqCst).min(addr_len);
        fill_rect(x + 44 + (cursor as u32) * 8, y + 94, 2, 20, COLOR_ACCENT);
    }
    drop(send_addr);

    draw_string(x + 36, y + 130, b"Amount", COLOR_TEXT_DIM);
    fill_rect(x + 36, y + 150, w - 72, 28, COLOR_BG);
    fill_rect(x + 36, y + 150, w - 72, 1, COLOR_BORDER);

    let send_amount = SEND_AMOUNT.lock();
    let amount_len = SEND_AMOUNT_LEN.load(Ordering::SeqCst);

    for (i, &ch) in send_amount[..amount_len].iter().enumerate() {
        draw_char(x + 44 + (i as u32) * 8, y + 156, ch, COLOR_TEXT_WHITE);
    }

    if field == 1 && INPUT_FOCUSED.load(Ordering::SeqCst) {
        let cursor = INPUT_CURSOR.load(Ordering::SeqCst).min(amount_len);
        fill_rect(x + 44 + (cursor as u32) * 8, y + 154, 2, 20, COLOR_ACCENT);
    }
    drop(send_amount);

    draw_string(x + w - 140, y + 156, b"ETH", COLOR_TEXT_DIM);

    draw_string(x + 36, y + 190, b"Gas Estimate", COLOR_TEXT_DIM);
    fill_rect(x + 36, y + 208, w - 72, 24, 0xFF1A1A2E);

    let gas_limit: u64 = 21000;
    let gas_price_gwei: u64 = 20;
    let total_gas_wei = gas_limit * gas_price_gwei * 1_000_000_000;
    let gas_eth = total_gas_wei / 1_000_000_000_000_000_000;
    let gas_remainder = (total_gas_wei % 1_000_000_000_000_000_000) / 1_000_000_000_000_000;

    let mut gas_str = [0u8; 32];
    let len = format_balance(&mut gas_str, gas_eth, gas_remainder);
    draw_string(x + 44, y + 212, &gas_str[..len], COLOR_TEXT_WHITE);
    draw_string(x + 44 + (len as u32 + 1) * 8, y + 212, b"ETH", COLOR_TEXT_DIM);

    let mut gwei_str = [0u8; 16];
    gwei_str[0] = b'(';
    let gwei_len = format_u64(&mut gwei_str[1..], gas_price_gwei);
    gwei_str[1 + gwei_len] = b' ';
    gwei_str[2 + gwei_len] = b'G';
    gwei_str[3 + gwei_len] = b'w';
    gwei_str[4 + gwei_len] = b'e';
    gwei_str[5 + gwei_len] = b'i';
    gwei_str[6 + gwei_len] = b')';
    draw_string(x + w - 120, y + 212, &gwei_str[..7 + gwei_len], COLOR_TEXT_DIM);

    fill_rect(x + w / 2 - 60, y + 290, 120, 36, COLOR_ACCENT);
    draw_string(x + w / 2 - 24, y + 300, b"Send", COLOR_BG);
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
    draw_string(x + 20, y + 20, b"Receive", COLOR_TEXT_WHITE);

    let state = WALLET_STATE.lock();
    if let Some(account) = state.get_active_account() {
        fill_rect(x + 20, y + 50, w - 40, 220, COLOR_CARD);

        draw_string(x + 36, y + 70, b"Your Address", COLOR_TEXT_DIM);

        let addr_hex = account.address_hex();

        if let Some(qr) = crate::graphics::qrcode::encode_qr(&addr_hex) {
            crate::graphics::qrcode::draw_qr(&qr, x + w / 2 - 82, y + 95, 5, 0xFF000000, 0xFFFFFFFF);
        }

        draw_string(x + 36, y + 230, &addr_hex, COLOR_TEXT_WHITE);

        draw_string(x + 36, y + 255, b"Scan QR code or share address", COLOR_TEXT_DIM);
    }
}

pub(super) fn draw_status_bar(x: u32, y: u32, w: u32) {
    use super::render::{COLOR_GREEN, COLOR_RED};

    fill_rect(x, y, w, 30, COLOR_SIDEBAR);

    let status = STATUS_MSG.lock();
    let status_len = STATUS_LEN.load(Ordering::SeqCst);
    let success = STATUS_SUCCESS.load(Ordering::SeqCst);

    if status_len > 0 {
        let color = if success { COLOR_GREEN } else { COLOR_RED };
        draw_string(x + 20, y + 9, &status[..status_len], color);
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

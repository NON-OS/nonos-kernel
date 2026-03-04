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
use crate::graphics::framebuffer::{fill_rect, COLOR_GREEN, COLOR_TEXT_WHITE, COLOR_ACCENT};
use crate::graphics::font::draw_char;
use crate::graphics::window::draw_string;

use super::state::*;
use super::types::*;
use super::render::{COLOR_BG, COLOR_CARD, COLOR_BORDER, COLOR_TEXT_DIM, COLOR_YELLOW, COLOR_RED, COLOR_SIDEBAR, format_balance};

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

        draw_string(x + 36, card_y + 12, &account.name[..account.name_len], COLOR_TEXT_WHITE);

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

pub(super) fn draw_send_view(x: u32, y: u32, w: u32, _h: u32) {
    draw_string(x + 20, y + 20, b"Send", COLOR_TEXT_WHITE);

    fill_rect(x + 20, y + 50, w - 40, 160, COLOR_CARD);

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

    fill_rect(x + w / 2 - 60, y + 230, 120, 36, COLOR_ACCENT);
    draw_string(x + w / 2 - 24, y + 240, b"Send", COLOR_BG);
}

pub(super) fn draw_receive_view(x: u32, y: u32, w: u32, _h: u32) {
    draw_string(x + 20, y + 20, b"Receive", COLOR_TEXT_WHITE);

    let state = WALLET_STATE.lock();
    if let Some(account) = state.get_active_account() {
        fill_rect(x + 20, y + 50, w - 40, 120, COLOR_CARD);

        draw_string(x + 36, y + 70, b"Your Address", COLOR_TEXT_DIM);

        let addr_hex = account.address_hex();
        draw_string(x + 36, y + 95, &addr_hex, COLOR_TEXT_WHITE);

        draw_string(x + 36, y + 130, b"Share this address to receive funds", COLOR_TEXT_DIM);
    }
}

pub(super) fn draw_transactions_view(x: u32, y: u32, w: u32, h: u32) {
    draw_string(x + 20, y + 20, b"Transactions", COLOR_TEXT_WHITE);

    let state = WALLET_STATE.lock();
    if let Some(account) = state.get_active_account() {
        if account.transactions.is_empty() {
            draw_string(x + 20, y + 60, b"No transactions yet", COLOR_TEXT_DIM);
        } else {
            for (i, tx) in account.transactions.iter().enumerate() {
                let tx_y = y + 50 + (i as u32) * 50;
                if tx_y + 45 > y + h {
                    break;
                }

                fill_rect(x + 20, tx_y, w - 40, 45, COLOR_CARD);

                let (label, color) = match tx.tx_type {
                    TransactionType::Send => (b"Sent    ", COLOR_RED),
                    TransactionType::Receive => (b"Received", COLOR_GREEN),
                    TransactionType::StealthSend => (b"Stealth ", COLOR_YELLOW),
                    TransactionType::StealthReceive => (b"Private ", COLOR_GREEN),
                    TransactionType::ContractCall => (b"Contract", COLOR_ACCENT),
                };
                draw_string(x + 36, tx_y + 10, label, color);

                let (eth, wei) = tx.value_eth();
                let mut value_str = [0u8; 32];
                let len = format_balance(&mut value_str, eth, wei / 1_000_000_000_000_000);
                draw_string(x + w - 140, tx_y + 10, &value_str[..len], COLOR_TEXT_WHITE);

                let status = if tx.confirmed { b"Confirmed" } else { b"Pending  " };
                let status_color = if tx.confirmed { COLOR_GREEN } else { COLOR_YELLOW };
                draw_string(x + 36, tx_y + 28, status, status_color);
            }
        }
    }
}

pub(super) fn draw_status_bar(x: u32, y: u32, w: u32) {
    fill_rect(x, y, w, 30, COLOR_SIDEBAR);

    let status = STATUS_MSG.lock();
    let status_len = STATUS_LEN.load(Ordering::SeqCst);
    let success = STATUS_SUCCESS.load(Ordering::SeqCst);

    if status_len > 0 {
        let color = if success { COLOR_GREEN } else { COLOR_RED };
        draw_string(x + 20, y + 9, &status[..status_len], color);
    }
}

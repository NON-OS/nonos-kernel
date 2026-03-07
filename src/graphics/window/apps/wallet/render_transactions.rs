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
 * Transaction history view rendering.
 *
 * Displays a scrollable list of transactions for the active account.
 * Each transaction card shows:
 * - Transaction type (send/receive/stealth/contract)
 * - Value in ETH
 * - From and To addresses (truncated)
 * - Transaction hash (first 8 bytes)
 * - Timestamp
 * - Confirmation status
 */

use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;

use super::state::*;
use super::types::{format_address, truncate_address, TransactionType};
use super::render::{
    format_balance, COLOR_ACCENT, COLOR_CARD, COLOR_GREEN, COLOR_RED,
    COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};

pub(super) fn draw_transactions_view(x: u32, y: u32, w: u32, h: u32) {
    draw_string(x + 20, y + 20, b"Transactions", COLOR_TEXT_WHITE);

    let state = WALLET_STATE.lock();
    if let Some(account) = state.get_active_account() {
        if account.transactions.is_empty() {
            draw_string(x + 20, y + 60, b"No transactions yet", COLOR_TEXT_DIM);
        } else {
            for (i, tx) in account.transactions.iter().enumerate() {
                let tx_y = y + 50 + (i as u32) * 80;
                if tx_y + 75 > y + h {
                    break;
                }

                fill_rect(x + 20, tx_y, w - 40, 75, COLOR_CARD);

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

                let from_hex = format_address(&tx.from);
                let to_hex = format_address(&tx.to);
                let from_short = truncate_address(&from_hex);
                let to_short = truncate_address(&to_hex);
                draw_string(x + 36, tx_y + 28, b"From:", COLOR_TEXT_DIM);
                draw_string(x + 80, tx_y + 28, &from_short, COLOR_TEXT_WHITE);
                draw_string(x + 200, tx_y + 28, b"To:", COLOR_TEXT_DIM);
                draw_string(x + 230, tx_y + 28, &to_short, COLOR_TEXT_WHITE);

                let mut hash_str = [0u8; 18];
                hash_str[0] = b'0';
                hash_str[1] = b'x';
                let hex_chars: &[u8; 16] = b"0123456789abcdef";
                for j in 0..8 {
                    hash_str[2 + j * 2] = hex_chars[(tx.hash[j] >> 4) as usize];
                    hash_str[2 + j * 2 + 1] = hex_chars[(tx.hash[j] & 0x0f) as usize];
                }
                draw_string(x + 36, tx_y + 46, b"Hash:", COLOR_TEXT_DIM);
                draw_string(x + 80, tx_y + 46, &hash_str, COLOR_TEXT_DIM);

                let mut ts_str = [0u8; 16];
                let ts_len = format_timestamp(&mut ts_str, tx.timestamp);
                draw_string(x + 200, tx_y + 46, &ts_str[..ts_len], COLOR_TEXT_DIM);

                let status = if tx.confirmed { b"Confirmed" } else { b"Pending  " };
                let status_color = if tx.confirmed { COLOR_GREEN } else { COLOR_YELLOW };
                draw_string(x + 36, tx_y + 60, status, status_color);
            }
        }
    }
}

fn format_timestamp(buf: &mut [u8; 16], timestamp: u64) -> usize {
    let mut idx = 0;
    let mut n = timestamp;
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 16];
    let mut digit_count = 0;
    while n > 0 && digit_count < 16 {
        digits[digit_count] = (n % 10) as u8;
        n /= 10;
        digit_count += 1;
    }
    for i in (0..digit_count).rev() {
        buf[idx] = b'0' + digits[i];
        idx += 1;
    }
    idx
}

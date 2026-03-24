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

extern crate alloc;
use alloc::vec::Vec;
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::draw_string;
use super::state::WALLET_STATE;
use super::types::truncate_address;
use super::render::{format_balance, COLOR_CARD, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_ACCENT};

pub(super) use super::render_send::draw_send_view;
pub(super) use super::render_receive::draw_receive_view;
pub(super) use super::render_zksync::draw_zksync_view;
pub(super) use super::render_status::draw_status_bar;

struct AccountDisplay { index: u32, name: [u8; 32], name_len: usize, addr_short: [u8; 13], eth: u64, eth_frac: u64, nox: u64, nox_frac: u64 }

pub(super) fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color); fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r { put_pixel(x + r - dx, y + r - dy, color); put_pixel(x + w - r + dx - 1, y + r - dy, color); put_pixel(x + r - dx, y + h - r + dy - 1, color); put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color); }}}
}

pub(super) fn draw_overview(x: u32, y: u32, w: u32, h: u32) {
    draw_string(x + 20, y + 20, b"Accounts", COLOR_TEXT_WHITE);
    draw_rounded_rect(x + w - 190, y + 15, 80, 32, 8, 0xFF34C759);
    draw_string(x + w - 165, y + 23, b"+ New", 0xFF000000);
    draw_rounded_rect(x + w - 100, y + 15, 80, 32, 8, COLOR_ACCENT);
    draw_string(x + w - 90, y + 23, b"Refresh", 0xFF000000);
    let accounts: Vec<AccountDisplay> = {
        let state = WALLET_STATE.lock();
        state.accounts.iter().map(|a| { let (eth, wei) = a.balance_eth(); let (nox, nox_w) = a.balance_nox(); AccountDisplay { index: a.index, name: a.name, name_len: a.name_len, addr_short: truncate_address(&a.address_hex()), eth, eth_frac: wei / 1_000_000_000_000_000, nox, nox_frac: nox_w / 1_000_000_000_000_000 } }).collect()
    };
    for (i, acc) in accounts.iter().enumerate() {
        let card_y = y + 55 + (i as u32) * 85;
        if card_y + 75 > y + h { break; }
        for shadow in 0..4u32 { draw_rounded_rect(x + 20 + shadow / 2, card_y + shadow + 2, w - 40, 75, 12, ((15 - shadow * 3) << 24) | 0x000000); }
        draw_rounded_rect(x + 20, card_y, w - 40, 75, 12, COLOR_CARD);
        fill_rect(x + 32, card_y + 12, 28, 28, 0xFF3A3A3C);
        let mut idx_str = [0u8; 4]; idx_str[0] = b'#'; let idx_len = format_u32(&mut idx_str[1..], acc.index);
        draw_string(x + 36, card_y + 18, &idx_str[..1 + idx_len], COLOR_TEXT_WHITE);
        draw_string(x + 68, card_y + 14, &acc.name[..acc.name_len], COLOR_TEXT_WHITE);
        draw_string(x + 68, card_y + 32, &acc.addr_short, COLOR_TEXT_DIM);
        let mut balance_str = [0u8; 32]; let len = format_balance(&mut balance_str, acc.eth, acc.eth_frac);
        draw_string(x + w - 140, card_y + 14, &balance_str[..len], COLOR_TEXT_WHITE);
        draw_string(x + w - 140 + (len as u32 + 1) * 8, card_y + 14, b"ETH", 0xFF34C759);
        let mut nox_str = [0u8; 32]; let nox_len = format_balance(&mut nox_str, acc.nox, acc.nox_frac);
        draw_string(x + w - 140, card_y + 32, &nox_str[..nox_len], COLOR_TEXT_WHITE);
        draw_string(x + w - 140 + (nox_len as u32 + 1) * 8, card_y + 32, b"NOX", 0xFFBF5AF2);
    }
}

pub(super) fn format_u32(buf: &mut [u8], n: u32) -> usize {
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut val = n; let mut digits = [0u8; 10]; let mut dc = 0;
    while val > 0 { digits[dc] = (val % 10) as u8; val /= 10; dc += 1; }
    for i in (0..dc).rev() { buf[dc - 1 - i] = b'0' + digits[i]; }
    dc
}

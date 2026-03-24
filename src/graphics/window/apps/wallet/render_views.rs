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
use super::render::*;

pub(super) use super::render_send::draw_send_view;
pub(super) use super::render_receive::draw_receive_view;
pub(super) use super::render_zksync::draw_zksync_view;
pub(super) use super::render_status::draw_status_bar;

struct AccountDisplay { index: u32, name: [u8; 32], name_len: usize, addr_short: [u8; 13], eth: u64, eth_frac: u64, nox: u64, nox_frac: u64, active: bool }

pub(super) fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r { for dx in 0..r { if dx * dx + dy * dy <= r * r {
        put_pixel(x + r - dx, y + r - dy, color);
        put_pixel(x + w - r + dx - 1, y + r - dy, color);
        put_pixel(x + r - dx, y + h - r + dy - 1, color);
        put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
    }}}
}

pub(super) fn draw_overview(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_section_header(x + 24, y + 20, b"Your Accounts");
    draw_premium_button(x + w - 200, y + 14, 85, 36, b"+ New", COLOR_GREEN, COLOR_GREEN_GLOW);
    draw_premium_button(x + w - 105, y + 14, 85, 36, b"Refresh", COLOR_ACCENT, COLOR_ACCENT_GLOW);
    let accounts: Vec<AccountDisplay> = {
        let state = WALLET_STATE.lock();
        let active_idx = state.active_account as u32;
        state.accounts.iter().map(|a| {
            let (eth, wei) = a.balance_eth();
            let (nox, nox_w) = a.balance_nox();
            AccountDisplay {
                index: a.index,
                name: a.name,
                name_len: a.name_len,
                addr_short: truncate_address(&a.address_hex()),
                eth,
                eth_frac: wei / 1_000_000_000_000_000,
                nox,
                nox_frac: nox_w / 1_000_000_000_000_000,
                active: a.index == active_idx,
            }
        }).collect()
    };
    for (i, acc) in accounts.iter().enumerate() {
        let card_y = y + 65 + (i as u32) * 100;
        draw_premium_account_card(x + 24, card_y, w - 48, 90, &acc);
    }
}

fn draw_section_header(x: u32, y: u32, text: &[u8]) {
    draw_string(x, y, text, COLOR_TEXT_WHITE);
    fill_rect(x, y + 20, 60, 2, COLOR_ACCENT);
    for i in 0..3 { fill_rect(x + 60 + i * 2, y + 20, 1, 2, blend_alpha(COLOR_ACCENT, 60 - i * 20)); }
}

fn draw_premium_button(x: u32, y: u32, w: u32, h: u32, text: &[u8], color: u32, glow: u32) {
    for i in 0..4 { draw_rounded_rect(x + i / 2, y + 3 + i, w, h, 10, blend_alpha(0x000000, 20 - i * 4)); }
    draw_rounded_rect(x, y, w, h, 10, color);
    draw_button_highlight(x, y, w, h, 10, glow);
    let text_x = x + (w - text.len() as u32 * 8) / 2;
    draw_string(text_x, y + (h - 12) / 2, text, 0xFF000000);
}

fn draw_button_highlight(x: u32, y: u32, w: u32, _h: u32, r: u32, glow: u32) {
    for row in 0..core::cmp::min(r, 8) {
        let alpha = 40 - row * 5;
        let in_radius = row < r;
        let start_x = if in_radius { x + r - isqrt(r * r - (r - row) * (r - row)) } else { x };
        let end_x = if in_radius { x + w - r + isqrt(r * r - (r - row) * (r - row)) } else { x + w };
        if end_x > start_x { fill_rect(start_x, y + row, end_x - start_x, 1, blend_alpha(glow, alpha)); }
    }
}

fn draw_premium_account_card(x: u32, y: u32, w: u32, h: u32, acc: &AccountDisplay) {
    for i in 0..6 { draw_rounded_rect(x + i / 2, y + 4 + i, w, h, 14, blend_alpha(0x000000, 25 - i * 4)); }
    let card_color = if acc.active { COLOR_CARD_ELEVATED } else { COLOR_CARD };
    draw_rounded_rect(x, y, w, h, 14, card_color);
    if acc.active {
        draw_card_glow(x, y, w, h, 14, COLOR_ACCENT);
        fill_rect(x, y + 20, 4, h - 40, COLOR_ACCENT);
    }
    draw_card_top_gradient(x, y, w, h, 14);
    let avatar_color = account_color(acc.index);
    draw_rounded_rect(x + 20, y + 18, 44, 44, 12, avatar_color);
    draw_avatar_gradient(x + 20, y + 18, 44, 44, 12);
    let mut idx_str = [0u8; 4];
    idx_str[0] = b'#';
    let idx_len = format_u32(&mut idx_str[1..], acc.index);
    draw_string(x + 30, y + 32, &idx_str[..1 + idx_len], COLOR_TEXT_WHITE);
    draw_string(x + 76, y + 22, &acc.name[..acc.name_len], COLOR_TEXT_WHITE);
    draw_string(x + 76, y + 42, &acc.addr_short, COLOR_TEXT_DIM);
    if acc.active {
        draw_rounded_rect(x + 76 + acc.name_len as u32 * 8 + 12, y + 20, 50, 20, 6, blend_alpha(COLOR_GREEN, 30));
        draw_string(x + 76 + acc.name_len as u32 * 8 + 18, y + 24, b"Active", COLOR_GREEN);
    }
    let mut eth_str = [0u8; 32];
    let eth_len = format_balance(&mut eth_str, acc.eth, acc.eth_frac);
    draw_string(x + w - 150, y + 22, &eth_str[..eth_len], COLOR_TEXT_WHITE);
    draw_string(x + w - 150 + (eth_len as u32 + 1) * 8, y + 22, b"ETH", COLOR_GREEN);
    let mut nox_str = [0u8; 32];
    let nox_len = format_balance(&mut nox_str, acc.nox, acc.nox_frac);
    draw_string(x + w - 150, y + 44, &nox_str[..nox_len], COLOR_TEXT_WHITE);
    draw_string(x + w - 150 + (nox_len as u32 + 1) * 8, y + 44, b"NOX", COLOR_PURPLE);
}

fn draw_card_glow(x: u32, y: u32, w: u32, h: u32, _r: u32, color: u32) {
    for i in 1..4 {
        fill_rect(x.saturating_sub(i), y, i, h, blend_alpha(color, 15 - i * 4));
        fill_rect(x + w, y, i, h, blend_alpha(color, 15 - i * 4));
        fill_rect(x, y.saturating_sub(i), w, i, blend_alpha(color, 15 - i * 4));
        fill_rect(x, y + h, w, i, blend_alpha(color, 15 - i * 4));
    }
}

fn draw_card_top_gradient(x: u32, y: u32, w: u32, _h: u32, r: u32) {
    for row in 0..core::cmp::min(20, r + 10) {
        let alpha = 12 - (row as u32 * 12 / 20);
        if alpha == 0 { break; }
        let in_radius = row < r;
        let start_x = if in_radius { x + r - isqrt(r * r - (r - row) * (r - row)) } else { x };
        let end_x = if in_radius { x + w - r + isqrt(r * r - (r - row) * (r - row)) } else { x + w };
        if end_x > start_x { fill_rect(start_x, y + row, end_x - start_x, 1, blend_alpha(0xFFFFFF, alpha)); }
    }
}

fn draw_avatar_gradient(x: u32, y: u32, w: u32, _h: u32, r: u32) {
    for row in 0..core::cmp::min(15, r + 5) {
        let alpha = 30 - row * 2;
        let in_radius = row < r;
        let start_x = if in_radius { x + r - isqrt(r * r - (r - row) * (r - row)) } else { x };
        let end_x = if in_radius { x + w - r + isqrt(r * r - (r - row) * (r - row)) } else { x + w };
        if end_x > start_x { fill_rect(start_x, y + row, end_x - start_x, 1, blend_alpha(0xFFFFFF, alpha)); }
    }
}

fn account_color(index: u32) -> u32 {
    let colors = [COLOR_ACCENT, COLOR_PURPLE, COLOR_GREEN, COLOR_YELLOW, COLOR_CYAN, COLOR_RED];
    colors[(index as usize) % colors.len()]
}

pub(super) fn format_u32(buf: &mut [u8], n: u32) -> usize {
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut val = n;
    let mut digits = [0u8; 10];
    let mut dc = 0;
    while val > 0 { digits[dc] = (val % 10) as u8; val /= 10; dc += 1; }
    for i in (0..dc).rev() { buf[dc - 1 - i] = b'0' + digits[i]; }
    dc
}

fn blend_alpha(color: u32, alpha: u32) -> u32 {
    let a = (alpha * 255 / 100).min(255);
    (a << 24) | (color & 0x00FFFFFF)
}

fn isqrt(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x { x = y; y = (x + n / x) / 2; }
    x
}

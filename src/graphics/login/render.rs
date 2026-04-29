// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::auth::{get_wallet_address, get_wallet_count};
use super::state::{get_screen_state, get_selected_wallet, ScreenState};
use crate::graphics::components::{primitives, text};
use crate::graphics::design_system::colors::{ACCENT, TEXT_PRIMARY, TEXT_SECONDARY};
use crate::graphics::framebuffer::dimensions;

const BG_COLOR: u32 = 0xFF0A0A10;
const CARD_BG: u32 = 0xF0181820;
const ITEM_BG: u32 = 0xFF1C1C24;
const SELECTED_BG: u32 = 0xFF2A3A4A;

pub fn draw() {
    let state = get_screen_state();
    if state == ScreenState::Hidden {
        return;
    }
    let (sw, sh) = dimensions();
    primitives::rect(0, 0, sw, sh, BG_COLOR);
    draw_logo(sw);
    match state {
        ScreenState::Welcome => draw_welcome(sw, sh),
        ScreenState::WalletSelect => draw_wallet_select(sw, sh),
        ScreenState::WalletCreate => draw_wallet_create(sw, sh),
        ScreenState::WalletImport => draw_wallet_import(sw, sh),
        _ => {}
    }
}

fn draw_logo(sw: u32) {
    let x = sw / 2 - 40;
    text::draw(x, 60, b"N\\xd8NOS", ACCENT);
    text::draw(x - 20, 90, b"Ephemeral OS", TEXT_SECONDARY);
}

fn draw_welcome(sw: u32, sh: u32) {
    let y = sh / 2 - 60;
    text::draw(sw / 2 - 60, y, b"Welcome to NONOS", TEXT_PRIMARY);
    draw_button(sw / 2 - 100, y + 60, 200, b"Select Wallet", false);
    draw_button(sw / 2 - 100, y + 110, 200, b"Create New Wallet", false);
    draw_button(sw / 2 - 100, y + 160, 200, b"Import Wallet", false);
}

fn draw_wallet_select(sw: u32, sh: u32) {
    let count = get_wallet_count();
    let selected = get_selected_wallet();
    let card_h = 60 + count as u32 * 56;
    let y = (sh - card_h) / 2;
    primitives::rounded_rect(sw / 2 - 180, y, 360, card_h, 16, CARD_BG);
    text::draw(sw / 2 - 60, y + 20, b"Select Wallet", TEXT_PRIMARY);
    for i in 0..count {
        let wy = y + 50 + i as u32 * 56;
        let is_sel = i == selected;
        let bg = if is_sel { SELECTED_BG } else { ITEM_BG };
        primitives::rounded_rect(sw / 2 - 160, wy, 320, 48, 8, bg);
        draw_wallet_item(sw / 2 - 150, wy + 8, i);
    }
}

fn draw_wallet_item(x: u32, y: u32, idx: u8) {
    primitives::rounded_rect(x, y, 32, 32, 16, ACCENT);
    let idx_char = b'1' + idx;
    text::draw(x + 12, y + 8, &[idx_char], 0xFF101018);
    if let Some(addr) = get_wallet_address(idx) {
        let mut addr_str = [0u8; 12];
        addr_str[0] = b'0';
        addr_str[1] = b'x';
        for i in 0..4 {
            addr_str[2 + i] = hex_char(addr[i] >> 4);
        }
        addr_str[6] = b'.';
        addr_str[7] = b'.';
        for i in 0..4 {
            addr_str[8 + i] = hex_char(addr[16 + i] & 0xF);
        }
        text::draw(x + 44, y + 8, &addr_str, TEXT_PRIMARY);
    }
}

fn hex_char(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

fn draw_wallet_create(sw: u32, sh: u32) {
    let y = sh / 2 - 40;
    text::draw(sw / 2 - 80, y, b"Creating new wallet...", TEXT_PRIMARY);
    text::draw(sw / 2 - 100, y + 40, b"Save your recovery phrase!", TEXT_SECONDARY);
}

fn draw_wallet_import(sw: u32, sh: u32) {
    let y = sh / 2 - 40;
    text::draw(sw / 2 - 80, y, b"Import from mnemonic", TEXT_PRIMARY);
    primitives::rounded_rect(sw / 2 - 180, y + 40, 360, 44, 8, ITEM_BG);
    text::draw(sw / 2 - 170, y + 54, b"Enter recovery phrase...", TEXT_SECONDARY);
}

fn draw_button(x: u32, y: u32, w: u32, label: &[u8], selected: bool) {
    let bg = if selected { ACCENT } else { ITEM_BG };
    let fg = if selected { 0xFF101018 } else { TEXT_PRIMARY };
    primitives::rounded_rect(x, y, w, 40, 8, bg);
    text::draw(x + w / 2 - (label.len() as u32 * 4), y + 12, label, fg);
}

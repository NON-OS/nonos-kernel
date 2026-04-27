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

use super::network::get_network;
use super::render::{
    COLOR_ACCENT, COLOR_BG, COLOR_CARD, COLOR_GREEN, COLOR_RED, COLOR_TEXT_DIM, COLOR_TEXT_WHITE,
    COLOR_YELLOW,
};
use super::state::{SHOW_PRIVATE_KEY, WALLET_STATE};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use core::sync::atomic::Ordering;

pub(super) fn draw_stealth_view(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_string(x + 20, y + 20, b"Stealth & ZK Privacy", COLOR_TEXT_WHITE);
    fill_rect(x + 20, y + 50, w - 40, 90, COLOR_CARD);
    draw_string(x + 36, y + 65, b"Stealth Addresses (EIP-5564)", COLOR_GREEN);
    draw_string(x + 36, y + 85, b"One-time addresses for unlinkable payments", COLOR_TEXT_DIM);
    let stealth_active = {
        let state = WALLET_STATE.lock();
        state.stealth_keypair.is_some()
    };
    if stealth_active {
        draw_string(x + 36, y + 110, b"[Active] Keys derived from master seed", COLOR_GREEN);
    } else {
        draw_string(x + 36, y + 110, b"Unlock wallet to enable stealth keys", COLOR_TEXT_DIM);
    }
    fill_rect(x + 20, y + 155, w - 40, 120, COLOR_CARD);
    draw_string(x + 36, y + 170, b"Zero-Knowledge Proofs", COLOR_ACCENT);
    draw_string(x + 36, y + 190, b"Groth16 proofs for private transactions", COLOR_TEXT_DIM);
    let (zk_init, circuits_ready, total_circuits) = super::zk::get_zk_status();
    if zk_init {
        let mut s = *b"ZK Engine Ready (X/Y circuits)";
        s[18] = b'0' + circuits_ready;
        s[20] = b'0' + total_circuits;
        draw_string(x + 36, y + 215, &s, COLOR_GREEN);
    } else {
        draw_string(x + 36, y + 215, b"ZK Engine: Not initialized", COLOR_YELLOW);
    }
    draw_string(x + 36, y + 240, b"Balance Ownership | Tx Auth | Sufficiency", COLOR_TEXT_DIM);
    fill_rect(x + 20, y + 290, (w - 50) / 2, 36, COLOR_ACCENT);
    draw_string(x + 36, y + 300, b"Generate Stealth Addr", 0xFF0D1117);
    fill_rect(x + 30 + (w - 50) / 2, y + 290, (w - 50) / 2, 36, COLOR_YELLOW);
    draw_string(x + 46 + (w - 50) / 2, y + 300, b"Init ZK Proofs", 0xFF0D1117);
    if stealth_active {
        draw_string(x + 20, y + 345, b"Your Stealth Meta-Address:", COLOR_TEXT_DIM);
        fill_rect(x + 20, y + 365, w - 40, 50, COLOR_CARD);
        let encoded = {
            let state = WALLET_STATE.lock();
            state.stealth_keypair.as_ref().map(|s| s.meta_address().encode())
        };
        if let Some(enc) = encoded {
            draw_string(x + 28, y + 378, &enc[..60.min(enc.len())], COLOR_TEXT_WHITE);
            if enc.len() > 60 {
                draw_string(x + 28, y + 395, &enc[60..], COLOR_TEXT_WHITE);
            }
        }
    }
    if h > 450 {
        fill_rect(x + 20, y + h - 85, w - 40, 70, COLOR_CARD);
        draw_string(x + 36, y + h - 70, b"Generate ZK Proof for Transaction", COLOR_TEXT_WHITE);
        draw_string(
            x + 36,
            y + h - 50,
            b"Prove balance sufficiency without revealing amount",
            COLOR_TEXT_DIM,
        );
        fill_rect(x + w - 160, y + h - 65, 120, 30, COLOR_GREEN);
        draw_string(x + w - 145, y + h - 57, b"Create Proof", 0xFF0D1117);
    }
}

pub(super) fn draw_settings_view(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_string(x + 20, y + 20, b"Settings", COLOR_TEXT_WHITE);
    let network = get_network();
    let network_name = network.name();
    fill_rect(x + 20, y + 50, w - 40, 50, COLOR_CARD);
    draw_string(x + 36, y + 60, b"Network (tap to switch)", COLOR_TEXT_WHITE);
    draw_string(x + 36, y + 78, network_name, COLOR_ACCENT);
    fill_rect(x + 20, y + 110, w - 40, 50, COLOR_CARD);
    draw_string(x + 36, y + 120, b"Security", COLOR_TEXT_WHITE);
    draw_string(x + 36, y + 138, b"Hardware-backed Keys", COLOR_TEXT_DIM);
    fill_rect(x + 20, y + 170, w - 40, 50, COLOR_CARD);
    draw_string(x + 36, y + 180, b"Currency", COLOR_TEXT_WHITE);
    draw_string(x + 36, y + 198, b"ETH / NOX", COLOR_TEXT_DIM);
    let export_y = y + 235;
    fill_rect(x + 20, export_y, w - 40, 70, COLOR_CARD);
    draw_string(x + 36, export_y + 10, b"Export Private Key", COLOR_YELLOW);
    let show_key = SHOW_PRIVATE_KEY.load(Ordering::Relaxed);
    if show_key {
        let key_hex = {
            let state = WALLET_STATE.lock();
            state.get_active_account().map(|a| a.private_key_hex())
        };
        if let Some(key) = key_hex {
            draw_string(x + 36, export_y + 30, key.as_bytes(), COLOR_TEXT_WHITE);
        } else {
            draw_string(x + 36, export_y + 30, b"No active account", COLOR_TEXT_DIM);
        }
        draw_string(x + 36, export_y + 50, b"[Click to hide]", COLOR_TEXT_DIM);
    } else {
        draw_string(x + 36, export_y + 30, b"Click to reveal (keep secure!)", COLOR_TEXT_DIM);
    }
    fill_rect(x + 20, y + h - 80, w - 40, 40, COLOR_RED);
    draw_string(x + w / 2 - 48, y + h - 68, b"Lock Wallet", COLOR_TEXT_WHITE);
}

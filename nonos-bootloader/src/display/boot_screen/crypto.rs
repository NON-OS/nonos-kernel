// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::constants::*;
use crate::display::font::draw_string;
use crate::display::gop::{get_dimensions, fill_rect};
use super::stages::get_stages_box_bottom;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

static HASH_REVEAL: AtomicU32 = AtomicU32::new(0);
static PANEL_DRAWN: AtomicBool = AtomicBool::new(false);

const PANEL_WIDTH: u32 = 280;
const PANEL_HEIGHT: u32 = 120;
const PANEL_MARGIN: u32 = 32;
const INNER_PAD: u32 = 12;
const PANEL_GAP: u32 = 16;
const LINE_HEIGHT: u32 = 24;

fn get_panel_pos() -> (u32, u32) {
    let (screen_w, _) = get_dimensions();
    let x = if screen_w > PANEL_WIDTH + PANEL_MARGIN {
        screen_w - PANEL_WIDTH - PANEL_MARGIN
    } else {
        0
    };
    let y = get_stages_box_bottom() + PANEL_GAP;
    (x, y)
}

fn draw_panel_bg() {
    if PANEL_DRAWN.swap(true, Ordering::SeqCst) {
        return;
    }
    let (px, py) = get_panel_pos();
    fill_rect(px, py, PANEL_WIDTH, PANEL_HEIGHT, COLOR_BOX_BG);
    fill_rect(px, py, PANEL_WIDTH, 3, COLOR_CRYPTO_CYAN);
    fill_rect(px, py + 36, PANEL_WIDTH, 1, COLOR_BORDER);
}

pub struct BootCryptoState {
    pub kernel_hash: [u8; 32],
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
    pub signature_valid: Option<bool>,
    pub zk_present: bool,
    pub zk_verified: Option<bool>,
    pub zk_program_hash: [u8; 32],
}

impl BootCryptoState {
    pub const fn new() -> Self {
        Self {
            kernel_hash: [0u8; 32],
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
            signature_valid: None,
            zk_present: false,
            zk_verified: None,
            zk_program_hash: [0u8; 32],
        }
    }
}

pub fn show_crypto_verification(crypto: &BootCryptoState) {
    draw_panel_bg();
    let (px, py) = get_panel_pos();

    draw_string(px + INNER_PAD, py + 10, b"Crypto Verification", COLOR_TEXT_PRIMARY);

    let hash_y = py + 44;
    fill_rect(px + 4, hash_y, PANEL_WIDTH - 8, LINE_HEIGHT, COLOR_BOX_BG);
    let mut hash_buf: [u8; 20] = *b"BLAKE3 .............";
    format_hash_into(&crypto.kernel_hash, &mut hash_buf[7..19]);
    draw_string(px + INNER_PAD, hash_y + 4, &hash_buf, COLOR_CRYPTO_CYAN);

    let sig_y = py + 68;
    fill_rect(px + 4, sig_y, PANEL_WIDTH - 8, LINE_HEIGHT, COLOR_BOX_BG);
    let (sig_label, sig_color) = match crypto.signature_valid {
        Some(true) => (b"Ed25519 VALID      ", COLOR_SUCCESS),
        Some(false) => (b"Ed25519 INVALID    ", COLOR_ERROR),
        None => (b"Ed25519 pending    ", COLOR_TEXT_DIM),
    };
    draw_string(px + INNER_PAD, sig_y + 4, sig_label, sig_color);

    let zk_y = py + 92;
    fill_rect(px + 4, zk_y, PANEL_WIDTH - 8, LINE_HEIGHT, COLOR_BOX_BG);
    let (zk_label, zk_color) = match (crypto.zk_present, crypto.zk_verified) {
        (true, Some(true)) => (b"ZK VERIFIED        ", COLOR_SUCCESS),
        (true, Some(false)) => (b"ZK FAILED          ", COLOR_ERROR),
        (true, None) => (b"ZK verifying       ", COLOR_WARNING),
        (false, _) => (b"ZK not present     ", COLOR_TEXT_MUTED),
    };
    draw_string(px + INNER_PAD, zk_y + 4, zk_label, zk_color);
}

fn format_hash_into(hash: &[u8], out: &mut [u8]) {
    const HEX: &[u8] = b"0123456789abcdef";
    let bytes_to_show = (out.len() / 2).min(hash.len());
    for i in 0..bytes_to_show {
        let b = hash[i];
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
}

pub fn animate_hash_reveal() {
    let current = HASH_REVEAL.load(Ordering::Relaxed);
    if current < 32 {
        HASH_REVEAL.store(current + 1, Ordering::Release);
    }
}

pub fn reset_hash_reveal() {
    HASH_REVEAL.store(0, Ordering::Release);
    PANEL_DRAWN.store(false, Ordering::Release);
}

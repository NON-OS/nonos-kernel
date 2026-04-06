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
use crate::display::gop::{get_dimensions, fill_rect, draw_rect};
use super::stages::get_stages_box_bottom;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

static HASH_REVEAL: AtomicU32 = AtomicU32::new(0);
static CRYPTO_BOX_DRAWN: AtomicBool = AtomicBool::new(false);

const CRYPTO_BOX_WIDTH: u32 = 200;
const CRYPTO_BOX_HEIGHT: u32 = 110;
const CRYPTO_BOX_PAD: u32 = 12;
const CRYPTO_BOX_GAP: u32 = 20;

fn get_crypto_box_pos() -> (u32, u32) {
    let (screen_w, _) = get_dimensions();
    let x = screen_w - CRYPTO_BOX_WIDTH - 50;
    let y = get_stages_box_bottom() + CRYPTO_BOX_GAP;
    (x, y)
}

fn draw_crypto_box() {
    if CRYPTO_BOX_DRAWN.swap(true, Ordering::SeqCst) {
        return;
    }
    let (bx, by) = get_crypto_box_pos();
    // Transparent - draw cyan accent stripe
    fill_rect(bx, by, 4, CRYPTO_BOX_HEIGHT, COLOR_CRYPTO_CYAN);
}

fn get_crypto_area() -> (u32, u32) {
    let (bx, by) = get_crypto_box_pos();
    (bx + CRYPTO_BOX_PAD + 4, by + CRYPTO_BOX_PAD)
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
    draw_crypto_box();
    let (cx, cy) = get_crypto_area();

    draw_string(cx, cy, b"Crypto Verification", COLOR_CRYPTO_CYAN);

    // Format hash: "BLAKE3 xxxx...xxxx"
    let mut hash_line = [b' '; 28];
    hash_line[..7].copy_from_slice(b"BLAKE3 ");
    let len = format_hash_short(&crypto.kernel_hash, &mut hash_line[7..]);
    draw_string(cx, cy + 24, &hash_line[..7 + len], COLOR_SUCCESS);

    let sig_status: (&[u8], u32) = match crypto.signature_valid {
        Some(true) => (b"Ed25519 VALID", COLOR_SUCCESS),
        Some(false) => (b"Ed25519 INVALID", COLOR_ERROR),
        None => (b"Ed25519 ...", COLOR_TEXT_DIM),
    };
    draw_string(cx, cy + 48, sig_status.0, sig_status.1);

    let zk_status: (&[u8], u32) = match (crypto.zk_present, crypto.zk_verified) {
        (true, Some(true)) => (b"ZK VERIFIED", COLOR_SUCCESS),
        (true, Some(false)) => (b"ZK FAILED", COLOR_ERROR),
        (true, None) => (b"ZK ...", COLOR_WARNING),
        (false, _) => (b"ZK not present", COLOR_TEXT_DIM),
    };
    draw_string(cx, cy + 72, zk_status.0, zk_status.1);
}

fn format_hash_short(hash: &[u8], out: &mut [u8]) -> usize {
    let hex = b"0123456789abcdef";
    let show = hash.len().min(6); // Show 6 bytes = 12 hex chars
    let mut pos = 0;
    for &b in hash[..show].iter() {
        if pos + 1 < out.len() {
            out[pos] = hex[(b >> 4) as usize];
            out[pos + 1] = hex[(b & 0xF) as usize];
            pos += 2;
        }
    }
    if pos + 3 <= out.len() {
        out[pos] = b'.';
        out[pos + 1] = b'.';
        out[pos + 2] = b'.';
        pos += 3;
    }
    pos
}

pub fn animate_hash_reveal() {
    let current = HASH_REVEAL.load(Ordering::Relaxed);
    if current < 32 {
        HASH_REVEAL.store(current + 1, Ordering::Release);
    }
}

pub fn reset_hash_reveal() {
    HASH_REVEAL.store(0, Ordering::Release);
}

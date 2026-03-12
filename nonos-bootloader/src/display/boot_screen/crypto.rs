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

/*
 * Cryptographic Verification Display.
 *
 * Shows hash, signature, and ZK verification status.
 */

use crate::display::constants::*;
use crate::display::font::draw_string;
use crate::display::gop::{fill_rect, get_dimensions};
use core::sync::atomic::{AtomicU32, Ordering};

static HASH_REVEAL: AtomicU32 = AtomicU32::new(0);

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
    let (width, height) = get_dimensions();
    if width == 0 {
        return;
    }

    let panel_x = 40u32;
    let crypto_y = height - 140;

    fill_rect(panel_x - 16, crypto_y - 16, 500, 2, COLOR_GLASS_BORDER);

    draw_string(panel_x, crypto_y, b"Cryptographic Verification", COLOR_ACCENT);

    let mut hash_line = [0u8; 48];
    hash_line[..7].copy_from_slice(b"BLAKE3 ");
    format_hash_short(&crypto.kernel_hash, &mut hash_line[7..]);
    draw_string(panel_x, crypto_y + 22, &hash_line, COLOR_SUCCESS);

    let sig_status = match crypto.signature_valid {
        Some(true) => (b"Ed25519 VALID              ", COLOR_SUCCESS),
        Some(false) => (b"Ed25519 INVALID            ", COLOR_ERROR),
        None => (b"Ed25519 verifying...       ", COLOR_TEXT_DIM),
    };
    draw_string(panel_x, crypto_y + 44, sig_status.0, sig_status.1);

    let zk_status = match (crypto.zk_present, crypto.zk_verified) {
        (true, Some(true)) => (b"ZK-SNARK VERIFIED          ", COLOR_SUCCESS),
        (true, Some(false)) => (b"ZK-SNARK FAILED            ", COLOR_ERROR),
        (true, None) => (b"ZK-SNARK verifying...      ", COLOR_WARNING),
        (false, _) => (b"ZK-SNARK not present       ", COLOR_TEXT_DIM),
    };
    draw_string(panel_x, crypto_y + 66, zk_status.0, zk_status.1);
}

fn format_hash_short(hash: &[u8], out: &mut [u8]) {
    let hex = b"0123456789abcdef";
    let show = hash.len().min(8);
    for (i, &b) in hash[..show].iter().enumerate() {
        if i * 2 + 1 < out.len() {
            out[i * 2] = hex[(b >> 4) as usize];
            out[i * 2 + 1] = hex[(b & 0xF) as usize];
        }
    }
    if show * 2 + 3 <= out.len() {
        out[show * 2] = b'.';
        out[show * 2 + 1] = b'.';
        out[show * 2 + 2] = b'.';
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
}

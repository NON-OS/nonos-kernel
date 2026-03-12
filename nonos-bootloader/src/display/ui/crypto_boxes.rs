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
 * Cryptographic Display Boxes.
 *
 * ZK proof and signature verification displays.
 */

use crate::display::constants::*;
use crate::display::font::{draw_hex_byte, draw_string};
use crate::display::gop::fill_rect;

pub fn draw_zk_box(
    x: u32,
    y: u32,
    label: &[u8],
    program_hash: Option<&[u8; 32]>,
    verified: Option<bool>,
) {
    fill_rect(x, y, 3, ZK_BOX_HEIGHT, COLOR_ZK_PURPLE);

    draw_string(x + 12, y + 6, label, COLOR_ZK_PURPLE);

    let status_y = y + 26;
    match verified {
        Some(true) => {
            draw_string(x + 12, status_y, b"VERIFIED (Groth16/BLS12-381)", COLOR_SUCCESS);
        }
        Some(false) => {
            draw_string(x + 12, status_y, b"VERIFICATION FAILED", COLOR_ERROR);
        }
        None => {
            draw_string(x + 12, status_y, b"VERIFYING...", COLOR_WARNING);
        }
    }

    if let Some(hash) = program_hash {
        draw_string(x + 12, y + 46, b"Circuit:", COLOR_TEXT_DIM);
        for (i, &byte) in hash[..8].iter().enumerate() {
            draw_hex_byte(x + 80 + (i as u32 * 18), y + 46, byte, COLOR_ZK_PURPLE);
        }
        draw_string(x + 80 + 8 * 18, y + 46, b"...", COLOR_TEXT_DIM);
    } else {
        draw_string(x + 12, y + 46, b"Groth16/BLS12-381 Attestation", COLOR_TEXT_DIM);
    }
}

pub fn draw_signature_box(x: u32, y: u32, sig_r: &[u8], sig_s: &[u8], verified: Option<bool>) {
    fill_rect(x, y, 3, SIG_BOX_HEIGHT, COLOR_ACCENT);

    draw_string(x + 12, y + 6, b"Ed25519 Signature", COLOR_ACCENT);

    draw_string(x + 12, y + 26, b"R:", COLOR_TEXT_DIM);
    for (i, &byte) in sig_r[..8.min(sig_r.len())].iter().enumerate() {
        draw_hex_byte(x + 36 + (i as u32 * 18), y + 26, byte, COLOR_HASH_BYTE);
    }
    draw_string(x + 36 + 8 * 18, y + 26, b"...", COLOR_TEXT_DIM);

    draw_string(x + 12, y + 44, b"S:", COLOR_TEXT_DIM);
    for (i, &byte) in sig_s[..8.min(sig_s.len())].iter().enumerate() {
        draw_hex_byte(x + 36 + (i as u32 * 18), y + 44, byte, COLOR_HASH_BYTE);
    }
    draw_string(x + 36 + 8 * 18, y + 44, b"...", COLOR_TEXT_DIM);

    match verified {
        Some(true) => draw_string(x + 12, y + 64, b"VALID", COLOR_SUCCESS),
        Some(false) => draw_string(x + 12, y + 64, b"INVALID", COLOR_ERROR),
        None => draw_string(x + 12, y + 64, b"VERIFYING...", COLOR_WARNING),
    }
}

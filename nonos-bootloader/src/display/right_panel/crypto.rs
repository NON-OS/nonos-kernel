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

use crate::display::font::draw_string;
use super::frame::RightPanelLayout;

const LINE_HEIGHT: u32 = 20;
const COLOR_LABEL: u32 = 0xFF6B7280;
const COLOR_HASH: u32 = 0xFF66FFFF;
const COLOR_OK: u32 = 0xFF00FF88;
const COLOR_PENDING: u32 = 0xFFFFAA00;

pub struct CryptoDisplay<'a> {
    pub kernel_hash: Option<&'a [u8; 32]>,
    pub signature_valid: Option<bool>,
    pub zk_valid: Option<bool>,
    pub tpm_measured: bool,
}

pub fn render_crypto_state(layout: &RightPanelLayout, state: &CryptoDisplay) {
    let mut y = layout.content_y + 20;

    draw_label(layout.content_x, y, b"Kernel Hash:");
    y += LINE_HEIGHT;
    render_hash(layout, y, state.kernel_hash);
    y += LINE_HEIGHT * 3;

    draw_label(layout.content_x, y, b"Ed25519 Signature:");
    y += LINE_HEIGHT;
    render_status(layout.content_x, y, state.signature_valid);
    y += LINE_HEIGHT + 10;

    draw_label(layout.content_x, y, b"ZK-SNARK Proof:");
    y += LINE_HEIGHT;
    render_status(layout.content_x, y, state.zk_valid);
    y += LINE_HEIGHT + 10;

    draw_label(layout.content_x, y, b"TPM Measurement:");
    y += LINE_HEIGHT;
    render_tpm(layout.content_x, y, state.tpm_measured);
}

fn draw_label(x: u32, y: u32, text: &[u8]) {
    draw_string(x, y, text, COLOR_LABEL);
}

fn render_hash(layout: &RightPanelLayout, y: u32, hash: Option<&[u8; 32]>) {
    match hash {
        Some(h) => {
            let mut hex = [0u8; 64];
            for (i, b) in h.iter().enumerate() {
                hex[i * 2] = to_hex_char(b >> 4);
                hex[i * 2 + 1] = to_hex_char(b & 0xF);
            }
            draw_string(layout.content_x + 8, y, &hex[..32], COLOR_HASH);
            draw_string(layout.content_x + 8, y + LINE_HEIGHT, &hex[32..], COLOR_HASH);
        }
        None => draw_string(layout.content_x + 8, y, b"Computing...", COLOR_PENDING),
    }
}

fn render_status(x: u32, y: u32, valid: Option<bool>) {
    let (text, color) = match valid {
        Some(true) => (b"VERIFIED" as &[u8], COLOR_OK),
        Some(false) => (b"FAILED" as &[u8], 0xFFFF4444),
        None => (b"PENDING" as &[u8], COLOR_PENDING),
    };
    draw_string(x + 8, y, text, color);
}

fn render_tpm(x: u32, y: u32, measured: bool) {
    let (text, color) = if measured {
        (b"EXTENDED" as &[u8], COLOR_OK)
    } else {
        (b"NOT AVAILABLE" as &[u8], COLOR_LABEL)
    };
    draw_string(x + 8, y, text, color);
}

fn to_hex_char(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

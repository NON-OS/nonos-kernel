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

use crate::display::crypto_screen::layout::CRYPTO_X;
use crate::display::crypto_screen::state::{CryptoScreenState, VerifyState};
use crate::display::font::draw_string;
use crate::display::gop::fill_rect;

const COL_TEAL: u32 = 0x66FFFF;
const COL_GREEN: u32 = 0x40FF80;
const COL_RED: u32 = 0xFF4040;
const COL_DIM: u32 = 0x606070;
const COL_WHITE: u32 = 0xE0E0F0;

pub fn render_blake3(state: &CryptoScreenState) {
    let y = 150;
    fill_rect(CRYPTO_X + 10, y, 3, 40, COL_TEAL);
    draw_string(CRYPTO_X + 20, y, b"BLAKE3-256 Hash", COL_WHITE);
    render_hash(CRYPTO_X + 20, y + 20, &state.blake3_hash, state.blake3_revealed);
    render_status(CRYPTO_X + 400, y, state.blake3_state);
}

pub fn render_ed25519(state: &CryptoScreenState) {
    let y = 210;
    fill_rect(CRYPTO_X + 10, y, 3, 60, COL_TEAL);
    draw_string(CRYPTO_X + 20, y, b"Ed25519 Signature", COL_WHITE);
    render_hash(CRYPTO_X + 20, y + 20, &state.ed25519_sig_r, 32);
    render_hash(CRYPTO_X + 20, y + 40, &state.ed25519_sig_s, 32);
    render_status(CRYPTO_X + 400, y, state.ed25519_state);
}

pub fn render_zk(state: &CryptoScreenState) {
    let y = 290;
    fill_rect(CRYPTO_X + 10, y, 3, 60, COL_TEAL);
    draw_string(CRYPTO_X + 20, y, b"ZK-SNARK Attestation", COL_WHITE);
    render_hash(CRYPTO_X + 20, y + 20, &state.zk_program_hash, 32);
    render_hash(CRYPTO_X + 20, y + 40, &state.zk_capsule, 32);
    render_status(CRYPTO_X + 400, y, state.zk_state);
}

fn render_hash(x: u32, y: u32, hash: &[u8; 32], revealed: u8) {
    let mut buf = [b'.'; 48];
    for i in 0..(revealed as usize).min(24) {
        buf[i * 2] = hex(hash[i] >> 4);
        buf[i * 2 + 1] = hex(hash[i] & 0x0F);
    }
    draw_string(x, y, &buf, COL_DIM);
}

fn hex(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

fn render_status(x: u32, y: u32, state: VerifyState) {
    let (text, color) = match state {
        VerifyState::Pending => (b"PENDING ", COL_DIM),
        VerifyState::Verifying => (b"CHECKING", COL_TEAL),
        VerifyState::Valid => (b"VALID   ", COL_GREEN),
        VerifyState::Invalid => (b"INVALID ", COL_RED),
        VerifyState::NotPresent => (b"N/A     ", COL_DIM),
    };
    draw_string(x, y, text, color);
}

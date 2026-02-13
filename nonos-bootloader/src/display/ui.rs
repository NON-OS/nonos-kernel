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

use super::constants::*;
use super::font::{draw_hex_byte, draw_string};
use super::gop::{draw_rect, fill_rect, put_pixel};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StageStatus {
    Pending,
    Running,
    Success,
    Failed,
}

const LOGO_TEAL: u32 = 0xFF66FFFF;
const LOGO_BLACK: u32 = 0xFF000000;

pub fn draw_logo(x: u32, y: u32) {
    let size: u32 = 100;
    let radius: u32 = 22;

    draw_filled_rounded_rect(x, y, size, size, radius, LOGO_TEAL);

    let cx = x + size / 2;
    let cy = y + size / 2;
    let ring_outer = 32u32;
    let ring_thick = 8u32;
    let ring_inner = ring_outer - ring_thick;

    for dy in 0..=ring_outer {
        for dx in 0..=ring_outer {
            let dist_sq = dx * dx + dy * dy;
            let outer_sq = ring_outer * ring_outer;
            let inner_sq = ring_inner * ring_inner;

            if dist_sq <= outer_sq && dist_sq >= inner_sq {
                put_pixel(cx + dx, cy + dy, LOGO_BLACK);
                if dx > 0 {
                    put_pixel(cx - dx, cy + dy, LOGO_BLACK);
                }
                if dy > 0 {
                    put_pixel(cx + dx, cy - dy, LOGO_BLACK);
                }
                if dx > 0 && dy > 0 {
                    put_pixel(cx - dx, cy - dy, LOGO_BLACK);
                }
            }
        }
    }

    let half_thick = 5i32;
    let extend = 12i32;

    let start_x = cx as i32 - ring_outer as i32 - extend;
    let start_y = cy as i32 + ring_outer as i32 + extend;
    let line_len = (ring_outer * 2) as i32 + extend * 2;

    for i in 0..=line_len {
        let line_x = start_x + i;
        let line_y = start_y - i;

        for t in -half_thick..=half_thick {
            let px = line_x + t;
            let py = line_y + t;

            if px >= x as i32 && px < (x + size) as i32 && py >= y as i32 && py < (y + size) as i32
            {
                if point_in_rounded_rect(px as u32, py as u32, x, y, size, size, radius) {
                    put_pixel(px as u32, py as u32, LOGO_BLACK);
                }
            }
        }
    }
}

fn draw_filled_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);

    fill_quarter_circle(x + r, y + r, r, color, true, true);
    fill_quarter_circle(x + w - r - 1, y + r, r, color, false, true);
    fill_quarter_circle(x + r, y + h - r - 1, r, color, true, false);
    fill_quarter_circle(x + w - r - 1, y + h - r - 1, r, color, false, false);
}

fn fill_quarter_circle(cx: u32, cy: u32, r: u32, color: u32, left: bool, top: bool) {
    let r_sq = r * r;
    for dy in 0..=r {
        for dx in 0..=r {
            if dx * dx + dy * dy <= r_sq {
                let px = if left { cx - dx } else { cx + dx };
                let py = if top { cy - dy } else { cy + dy };
                put_pixel(px, py, color);
            }
        }
    }
}

fn point_in_rounded_rect(px: u32, py: u32, x: u32, y: u32, w: u32, h: u32, r: u32) -> bool {
    if px < x || px >= x + w || py < y || py >= y + h {
        return false;
    }

    let in_left = px < x + r;
    let in_right = px >= x + w - r;
    let in_top = py < y + r;
    let in_bottom = py >= y + h - r;

    if in_left && in_top {
        let dx = (x + r) as i32 - px as i32;
        let dy = (y + r) as i32 - py as i32;
        return (dx * dx + dy * dy) as u32 <= r * r;
    }
    if in_right && in_top {
        let dx = px as i32 - (x + w - r - 1) as i32;
        let dy = (y + r) as i32 - py as i32;
        return (dx * dx + dy * dy) as u32 <= r * r;
    }
    if in_left && in_bottom {
        let dx = (x + r) as i32 - px as i32;
        let dy = py as i32 - (y + h - r - 1) as i32;
        return (dx * dx + dy * dy) as u32 <= r * r;
    }
    if in_right && in_bottom {
        let dx = px as i32 - (x + w - r - 1) as i32;
        let dy = py as i32 - (y + h - r - 1) as i32;
        return (dx * dx + dy * dy) as u32 <= r * r;
    }

    true
}

pub fn draw_progress_bar(x: u32, y: u32, w: u32, h: u32, progress: u32, max: u32, color: u32) {
    fill_rect(x, y, w, h, COLOR_PROGRESS_BG);

    if max > 0 && progress > 0 {
        let fill_w = (w * progress.min(max)) / max;
        fill_rect(x, y, fill_w, h, color);
    }

    draw_rect(x, y, w, h, COLOR_BORDER);
}

pub fn draw_stage_box(x: u32, y: u32, label: &[u8], status: StageStatus) {
    let (status_color, status_text): (u32, &[u8]) = match status {
        StageStatus::Pending => (COLOR_TEXT_DIM, b"       "),
        StageStatus::Running => (COLOR_ACCENT, b"  ...  "),
        StageStatus::Success => (COLOR_SUCCESS, b"  OK   "),
        StageStatus::Failed => (COLOR_ERROR, b" FAIL  "),
    };

    fill_rect(x, y, STATUS_BOX_WIDTH, STATUS_BOX_HEIGHT, COLOR_BOX_BG);

    let indicator_color = match status {
        StageStatus::Pending => COLOR_TEXT_DIM,
        StageStatus::Running => COLOR_ACCENT,
        StageStatus::Success => COLOR_SUCCESS,
        StageStatus::Failed => COLOR_ERROR,
    };
    fill_rect(x, y, 3, STATUS_BOX_HEIGHT, indicator_color);

    draw_string(x + 12, y + 4, label, COLOR_TEXT_PRIMARY);

    draw_string(x + STATUS_BOX_WIDTH - 70, y + 4, status_text, status_color);
}

pub fn draw_hash_box(x: u32, y: u32, label: &[u8], hash: &[u8; 32], revealed: usize) {
    fill_rect(x, y, HASH_BOX_WIDTH, HASH_BOX_HEIGHT, COLOR_BOX_BG);
    fill_rect(x, y, 3, HASH_BOX_HEIGHT, COLOR_CRYPTO_CYAN);

    draw_string(x + 12, y + 6, label, COLOR_CRYPTO_CYAN);

    let hash_y = y + 28;
    for (i, &byte) in hash[..16.min(hash.len())].iter().enumerate() {
        let bx = x + 12 + (i as u32 * 26);
        let color = if i < revealed {
            COLOR_HASH_BYTE
        } else {
            COLOR_TEXT_DIM
        };
        draw_hex_byte(bx, hash_y, byte, color);
    }

    if hash.len() > 16 {
        draw_string(x + 12 + 16 * 26, hash_y, b"...", COLOR_TEXT_DIM);
    }
}

pub fn draw_zk_box(
    x: u32,
    y: u32,
    label: &[u8],
    program_hash: Option<&[u8; 32]>,
    verified: Option<bool>,
) {
    fill_rect(x, y, HASH_BOX_WIDTH, ZK_BOX_HEIGHT, COLOR_BOX_BG);
    fill_rect(x, y, 3, ZK_BOX_HEIGHT, COLOR_ZK_PURPLE);

    draw_string(x + 12, y + 6, label, COLOR_ZK_PURPLE);

    let status_y = y + 26;
    match verified {
        Some(true) => {
            draw_string(
                x + 12,
                status_y,
                b"VERIFIED (Groth16/BLS12-381)",
                COLOR_SUCCESS,
            );
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
        draw_string(
            x + 12,
            y + 46,
            b"Groth16/BLS12-381 Attestation",
            COLOR_TEXT_DIM,
        );
    }
}

pub fn draw_signature_box(x: u32, y: u32, sig_r: &[u8], sig_s: &[u8], verified: Option<bool>) {
    fill_rect(x, y, HASH_BOX_WIDTH, SIG_BOX_HEIGHT, COLOR_BOX_BG);
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

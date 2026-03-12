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
 * UI Box Components.
 *
 * Status boxes, hash displays, crypto verification boxes.
 */

use super::types::StageStatus;
use crate::display::constants::*;
use crate::display::font::{draw_hex_byte, draw_string};
use crate::display::gop::fill_rect;

pub fn draw_stage_box(x: u32, y: u32, label: &[u8], status: StageStatus) {
    let (status_color, status_text): (u32, &[u8]) = match status {
        StageStatus::Pending => (COLOR_TEXT_DIM, b"       "),
        StageStatus::Running => (COLOR_ACCENT, b"  ...  "),
        StageStatus::Success => (COLOR_SUCCESS, b"  OK   "),
        StageStatus::Failed => (COLOR_ERROR, b" FAIL  "),
    };

    fill_rect(x, y, STATUS_BOX_WIDTH, STATUS_BOX_HEIGHT, COLOR_GLASS_BG);

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
    fill_rect(x, y, HASH_BOX_WIDTH, HASH_BOX_HEIGHT, COLOR_GLASS_BG);
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

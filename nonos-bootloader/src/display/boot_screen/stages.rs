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
use crate::display::font::{draw_string, CHAR_HEIGHT};
use crate::display::gop::get_dimensions;
use crate::display::ui::StageStatus;
use core::sync::atomic::{AtomicU8, Ordering};

static CURRENT_STAGE: AtomicU8 = AtomicU8::new(STAGE_INIT);

const MARGIN: u32 = 30;
const HEADER_H: u32 = 32;
const PAD: u32 = 16;

fn get_stages_area() -> (u32, u32) {
    let (screen_w, _) = get_dimensions();
    let x = (screen_w / 2) + (MARGIN / 2) + PAD;
    let y = MARGIN + HEADER_H + PAD;
    (x, y)
}

pub fn update_stage(stage: u8, status: StageStatus) {
    let (width, _) = get_dimensions();
    if width == 0 {
        return;
    }

    CURRENT_STAGE.store(stage, Ordering::Release);

    let (panel_x, base_y) = get_stages_area();

    let (offset, label): (u32, &[u8]) = match stage {
        STAGE_UEFI => (0, b"UEFI Services"),
        STAGE_SECURITY => (1, b"Security Policy"),
        STAGE_HARDWARE => (2, b"Hardware Init"),
        STAGE_KERNEL_LOAD => (3, b"Kernel Load"),
        STAGE_BLAKE3_HASH => (4, b"BLAKE3 Hash"),
        STAGE_ED25519_VERIFY => (5, b"Ed25519 Verify"),
        STAGE_ZK_VERIFY => (6, b"ZK Attestation"),
        STAGE_ELF_PARSE => (7, b"ELF Parse"),
        STAGE_HANDOFF => (8, b"Kernel Handoff"),
        STAGE_COMPLETE => (9, b"Boot Complete"),
        _ => return,
    };

    let y = base_y + offset * (CHAR_HEIGHT + 4);

    let (indicator, color) = match status {
        StageStatus::Pending => (b"   ", COLOR_TEXT_DIM),
        StageStatus::Running => (b" > ", COLOR_WARNING),
        StageStatus::Success => (b" + ", COLOR_SUCCESS),
        StageStatus::Failed => (b" X ", COLOR_ERROR),
    };

    draw_string(panel_x, y, indicator, color);
    draw_string(panel_x + 24, y, label, color);
}

pub fn get_current_stage() -> u8 {
    CURRENT_STAGE.load(Ordering::Relaxed)
}

pub fn reset_stage() {
    CURRENT_STAGE.store(STAGE_INIT, Ordering::Release);
}

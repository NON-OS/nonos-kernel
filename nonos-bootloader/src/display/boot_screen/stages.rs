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
use crate::display::gop::{get_dimensions, fill_rect};
use crate::display::ui::StageStatus;
use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};

static CURRENT_STAGE: AtomicU8 = AtomicU8::new(STAGE_INIT);
static STAGES_BOX_DRAWN: AtomicBool = AtomicBool::new(false);

pub const STAGES_BOX_WIDTH: u32 = 280;
pub const STAGES_BOX_HEIGHT: u32 = 320;
const STAGES_BOX_PAD: u32 = 16;

fn get_stages_box_pos() -> (u32, u32) {
    let (screen_w, _) = get_dimensions();
    let x = screen_w - STAGES_BOX_WIDTH - 40;
    let y = 100;
    (x, y)
}

pub fn get_stages_box_bottom() -> u32 {
    let (_, y) = get_stages_box_pos();
    y + STAGES_BOX_HEIGHT
}

fn draw_stages_box() {
    if STAGES_BOX_DRAWN.swap(true, Ordering::SeqCst) {
        return;
    }
    let (bx, by) = get_stages_box_pos();
    // Transparent background - only draw accent stripe
    fill_rect(bx, by, 4, STAGES_BOX_HEIGHT, COLOR_ACCENT);
}

fn get_stages_area() -> (u32, u32) {
    let (bx, by) = get_stages_box_pos();
    (bx + STAGES_BOX_PAD + 4, by + STAGES_BOX_PAD)
}

pub fn update_stage(stage: u8, status: StageStatus) {
    let (width, _) = get_dimensions();
    if width == 0 {
        return;
    }

    draw_stages_box();
    CURRENT_STAGE.store(stage, Ordering::Release);

    let (panel_x, base_y) = get_stages_area();

    // Draw title on first call
    static TITLE_DRAWN: AtomicBool = AtomicBool::new(false);
    if !TITLE_DRAWN.swap(true, Ordering::SeqCst) {
        draw_string(panel_x, base_y, b"Boot Stages", COLOR_ACCENT);
    }

    let (offset, label): (u32, &[u8]) = match stage {
        STAGE_UEFI => (1, b"UEFI Services"),
        STAGE_SECURITY => (2, b"Security"),
        STAGE_HARDWARE => (3, b"Hardware Init"),
        STAGE_KERNEL_LOAD => (4, b"Kernel Load"),
        STAGE_BLAKE3_HASH => (5, b"BLAKE3 Hash"),
        STAGE_ED25519_VERIFY => (6, b"Ed25519 Verify"),
        STAGE_ZK_VERIFY => (7, b"ZK Attestation"),
        STAGE_ELF_PARSE => (8, b"ELF Parse"),
        STAGE_HANDOFF => (9, b"Kernel Handoff"),
        STAGE_COMPLETE => (10, b"Boot Complete"),
        _ => return,
    };

    let y = base_y + offset * (CHAR_HEIGHT + 4);

    let (indicator, color) = match status {
        StageStatus::Pending => (b"  ", COLOR_TEXT_DIM),
        StageStatus::Running => (b"> ", COLOR_WARNING),
        StageStatus::Success => (b"+ ", COLOR_SUCCESS),
        StageStatus::Failed => (b"X ", COLOR_ERROR),
    };

    draw_string(panel_x, y, indicator, color);
    draw_string(panel_x + 18, y, label, color);
}

pub fn get_current_stage() -> u8 {
    CURRENT_STAGE.load(Ordering::Relaxed)
}

pub fn reset_stage() {
    CURRENT_STAGE.store(STAGE_INIT, Ordering::Release);
}

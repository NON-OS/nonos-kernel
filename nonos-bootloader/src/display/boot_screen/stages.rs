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
static PANEL_DRAWN: AtomicBool = AtomicBool::new(false);

const PANEL_WIDTH: u32 = 320;
const PANEL_HEIGHT: u32 = 380;
const PANEL_MARGIN: u32 = 48;
const INNER_PAD: u32 = 24;
const LINE_HEIGHT: u32 = 28;
const HEADER_HEIGHT: u32 = 48;

fn get_panel_pos() -> (u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let x = screen_w - PANEL_WIDTH - PANEL_MARGIN;
    let y = (screen_h - PANEL_HEIGHT) / 2;
    (x, y)
}

pub fn get_stages_box_bottom() -> u32 {
    let (_, y) = get_panel_pos();
    y + PANEL_HEIGHT
}

fn draw_panel_background() {
    if PANEL_DRAWN.swap(true, Ordering::SeqCst) {
        return;
    }
    let (px, py) = get_panel_pos();
    fill_rect(px, py, PANEL_WIDTH, PANEL_HEIGHT, COLOR_BOX_BG);
    fill_rect(px, py, PANEL_WIDTH, 2, COLOR_ACCENT);
    fill_rect(px, py + HEADER_HEIGHT, PANEL_WIDTH, 1, COLOR_BORDER);
}

fn draw_header() {
    let (px, py) = get_panel_pos();
    draw_string(px + INNER_PAD, py + 16, b"Boot Sequence", COLOR_TEXT_PRIMARY);
}

pub fn update_stage(stage: u8, status: StageStatus) {
    let (width, _) = get_dimensions();
    if width == 0 {
        return;
    }

    draw_panel_background();

    static HEADER_DONE: AtomicBool = AtomicBool::new(false);
    if !HEADER_DONE.swap(true, Ordering::SeqCst) {
        draw_header();
    }

    CURRENT_STAGE.store(stage, Ordering::Release);

    let (px, py) = get_panel_pos();
    let content_y = py + HEADER_HEIGHT + 16;

    let stages: [(u8, &[u8]); 10] = [
        (STAGE_UEFI, b"UEFI Services"),
        (STAGE_SECURITY, b"Security Policy"),
        (STAGE_HARDWARE, b"Hardware Init"),
        (STAGE_KERNEL_LOAD, b"Kernel Load"),
        (STAGE_BLAKE3_HASH, b"BLAKE3 Integrity"),
        (STAGE_ED25519_VERIFY, b"Ed25519 Signature"),
        (STAGE_ZK_VERIFY, b"ZK Attestation"),
        (STAGE_ELF_PARSE, b"ELF Validation"),
        (STAGE_HANDOFF, b"Kernel Handoff"),
        (STAGE_COMPLETE, b"Boot Complete"),
    ];

    for (i, (s, label)) in stages.iter().enumerate() {
        if *s != stage {
            continue;
        }
        let y = content_y + (i as u32) * LINE_HEIGHT;
        let (indicator, bg_color, text_color) = match status {
            StageStatus::Pending => (b"   ", COLOR_BOX_BG, COLOR_TEXT_MUTED),
            StageStatus::Running => (b" > ", COLOR_WARNING, COLOR_TEXT_WHITE),
            StageStatus::Success => (b" + ", COLOR_SUCCESS, COLOR_TEXT_PRIMARY),
            StageStatus::Failed => (b" X ", COLOR_ERROR, COLOR_TEXT_WHITE),
        };
        fill_rect(px + 8, y - 2, PANEL_WIDTH - 16, LINE_HEIGHT - 4, COLOR_BOX_BG);
        if status == StageStatus::Running || status == StageStatus::Success || status == StageStatus::Failed {
            fill_rect(px + 8, y - 2, 4, LINE_HEIGHT - 4, bg_color);
        }
        draw_string(px + INNER_PAD, y, indicator, bg_color);
        draw_string(px + INNER_PAD + 24, y, *label, text_color);
    }
}

pub fn get_current_stage() -> u8 {
    CURRENT_STAGE.load(Ordering::Relaxed)
}

pub fn reset_stage() {
    CURRENT_STAGE.store(STAGE_INIT, Ordering::Release);
}

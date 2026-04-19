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
use crate::display::gop::{get_dimensions, fill_rect};
use crate::display::ui::StageStatus;
use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};

static CURRENT_STAGE: AtomicU8 = AtomicU8::new(STAGE_INIT);
static PANEL_DRAWN: AtomicBool = AtomicBool::new(false);
static HEADER_DONE: AtomicBool = AtomicBool::new(false);

const PANEL_WIDTH: u32 = 280;
const PANEL_HEIGHT: u32 = 360;
const PANEL_MARGIN: u32 = 32;
const INNER_PAD: u32 = 16;
const LINE_HEIGHT: u32 = 30;
const HEADER_HEIGHT: u32 = 44;

const CRYPTO_PANEL_HEIGHT: u32 = 120;
const CRYPTO_PANEL_GAP: u32 = 16;
const TOTAL_PANELS_HEIGHT: u32 = PANEL_HEIGHT + CRYPTO_PANEL_GAP + CRYPTO_PANEL_HEIGHT;

const STAGE_LABELS: [&[u8]; 10] = [
    b"UEFI Services",
    b"Security Policy",
    b"Hardware Init",
    b"Kernel Load",
    b"BLAKE3 Hash",
    b"Ed25519 Verify",
    b"ZK Attestation",
    b"ELF Parse",
    b"Kernel Handoff",
    b"Boot Complete",
];

fn get_panel_pos() -> (u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let x = if screen_w > PANEL_WIDTH + PANEL_MARGIN {
        screen_w - PANEL_WIDTH - PANEL_MARGIN
    } else {
        0
    };
    let y = if screen_h > TOTAL_PANELS_HEIGHT + PANEL_MARGIN * 2 {
        (screen_h - TOTAL_PANELS_HEIGHT) / 2
    } else if screen_h > PANEL_MARGIN {
        PANEL_MARGIN
    } else {
        0
    };
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
    fill_rect(px, py, PANEL_WIDTH, 3, COLOR_ACCENT);
    fill_rect(px, py + HEADER_HEIGHT, PANEL_WIDTH, 1, COLOR_BORDER);
}

fn draw_header() {
    if HEADER_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    let (px, py) = get_panel_pos();
    draw_string(px + INNER_PAD, py + 14, b"Boot Sequence", COLOR_TEXT_PRIMARY);
}

fn stage_index(stage: u8) -> Option<usize> {
    match stage {
        STAGE_UEFI => Some(0),
        STAGE_SECURITY => Some(1),
        STAGE_HARDWARE => Some(2),
        STAGE_KERNEL_LOAD => Some(3),
        STAGE_BLAKE3_HASH => Some(4),
        STAGE_ED25519_VERIFY => Some(5),
        STAGE_ZK_VERIFY => Some(6),
        STAGE_ELF_PARSE => Some(7),
        STAGE_HANDOFF => Some(8),
        STAGE_COMPLETE => Some(9),
        _ => None,
    }
}

pub fn update_stage(stage: u8, status: StageStatus) {
    let (width, _) = get_dimensions();
    if width == 0 {
        return;
    }
    draw_panel_background();
    draw_header();
    CURRENT_STAGE.store(stage, Ordering::Release);

    let idx = match stage_index(stage) {
        Some(i) => i,
        None => return,
    };

    let (px, py) = get_panel_pos();
    let content_y = py + HEADER_HEIGHT + 12;
    let y = content_y + (idx as u32) * LINE_HEIGHT;

    fill_rect(px + 4, y, PANEL_WIDTH - 8, LINE_HEIGHT - 4, COLOR_BOX_BG);

    let (indicator, ind_color, text_color) = match status {
        StageStatus::Pending => (b"  ", COLOR_TEXT_MUTED, COLOR_TEXT_MUTED),
        StageStatus::Running => (b"> ", COLOR_WARNING, COLOR_TEXT_WHITE),
        StageStatus::Success => (b"+ ", COLOR_SUCCESS, COLOR_TEXT_PRIMARY),
        StageStatus::Failed => (b"X ", COLOR_ERROR, COLOR_TEXT_WHITE),
    };

    if status == StageStatus::Running || status == StageStatus::Success || status == StageStatus::Failed {
        fill_rect(px + 4, y, 3, LINE_HEIGHT - 4, ind_color);
    }

    draw_string(px + INNER_PAD, y + 4, indicator, ind_color);
    draw_string(px + INNER_PAD + 16, y + 4, STAGE_LABELS[idx], text_color);
}

pub fn get_current_stage() -> u8 {
    CURRENT_STAGE.load(Ordering::Relaxed)
}

pub fn reset_stage() {
    CURRENT_STAGE.store(STAGE_INIT, Ordering::Release);
    PANEL_DRAWN.store(false, Ordering::Release);
    HEADER_DONE.store(false, Ordering::Release);
}

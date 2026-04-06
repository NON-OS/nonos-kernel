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
use crate::display::gop::{fill_rect, get_dimensions};
use core::sync::atomic::{AtomicU32, Ordering};

static ANIMATION_FRAME: AtomicU32 = AtomicU32::new(0);

const MARGIN: u32 = 30;
const PAD: u32 = 16;

fn get_right_panel_bounds() -> (u32, u32, u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let x = (screen_w / 2) + (MARGIN / 2);
    let width = (screen_w / 2) - MARGIN - (MARGIN / 2);
    (x + PAD, MARGIN + PAD, width - PAD * 2, screen_h - MARGIN * 2 - PAD * 2)
}

pub fn draw_boot_progress(progress: u32, total: u32) {
    let (cx, _cy, cw, ch) = get_right_panel_bounds();
    let bar_y = MARGIN + ch - 16;

    fill_rect(cx, bar_y, cw, 8, COLOR_PROGRESS_BG);

    if total > 0 && progress > 0 {
        let fill = (cw * progress.min(total)) / total;
        fill_rect(cx, bar_y, fill, 8, COLOR_ACCENT);
    }
}

pub fn show_handoff_message() {
    let (cx, _cy, _cw, ch) = get_right_panel_bounds();
    let y = MARGIN + ch - 50;
    // Transparent background
    draw_string(cx + 8, y + 4, b"Transferring to kernel...", COLOR_SUCCESS);
}

pub fn show_error_screen(error: &[u8]) {
    let (cx, cy, cw, _ch) = get_right_panel_bounds();
    let panel_h = 80;
    let panel_y = cy + 100;
    fill_rect(cx, panel_y, cw, panel_h, COLOR_ERROR_BG);
    fill_rect(cx, panel_y, cw, 3, COLOR_ERROR);
    draw_string(cx + 16, panel_y + 20, b"BOOT FAILED", COLOR_TEXT_WHITE);
    draw_string(cx + 16, panel_y + 44, error, COLOR_TEXT_WHITE);
}

pub fn tick_animation() {
    let _ = ANIMATION_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub fn reset_animation() {
    ANIMATION_FRAME.store(0, Ordering::Release);
}

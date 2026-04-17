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

const BAR_WIDTH: u32 = 400;
const BAR_HEIGHT: u32 = 4;
const BAR_MARGIN_BOTTOM: u32 = 80;

fn get_progress_pos() -> (u32, u32) {
    let (screen_w, screen_h) = get_dimensions();
    let x = (screen_w - BAR_WIDTH) / 2;
    let y = screen_h - BAR_MARGIN_BOTTOM;
    (x, y)
}

pub fn draw_boot_progress(progress: u32, total: u32) {
    let (bar_x, bar_y) = get_progress_pos();
    fill_rect(bar_x, bar_y, BAR_WIDTH, BAR_HEIGHT, COLOR_PROGRESS_BG);
    if total > 0 && progress > 0 {
        let fill = (BAR_WIDTH * progress.min(total)) / total;
        fill_rect(bar_x, bar_y, fill, BAR_HEIGHT, COLOR_ACCENT);
    }
}

pub fn show_handoff_message() {
    let (screen_w, screen_h) = get_dimensions();
    let msg = b"Transferring to kernel...";
    let msg_width = msg.len() as u32 * 8;
    let x = (screen_w - msg_width) / 2;
    let y = screen_h - BAR_MARGIN_BOTTOM - 32;
    draw_string(x, y, msg, COLOR_SUCCESS);
}

pub fn show_error_screen(error: &[u8]) {
    let (screen_w, screen_h) = get_dimensions();
    let panel_w = 480;
    let panel_h = 120;
    let px = (screen_w - panel_w) / 2;
    let py = (screen_h - panel_h) / 2;
    fill_rect(px, py, panel_w, panel_h, COLOR_ERROR_BG);
    fill_rect(px, py, panel_w, 3, COLOR_ERROR);
    fill_rect(px, py, 3, panel_h, COLOR_ERROR);
    fill_rect(px + panel_w - 3, py, 3, panel_h, COLOR_ERROR);
    fill_rect(px, py + panel_h - 3, panel_w, 3, COLOR_ERROR);
    draw_string(px + 24, py + 28, b"BOOT FAILED", COLOR_TEXT_WHITE);
    draw_string(px + 24, py + 60, error, COLOR_TEXT_DIM);
}

pub fn tick_animation() {
    let _ = ANIMATION_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub fn reset_animation() {
    ANIMATION_FRAME.store(0, Ordering::Release);
}

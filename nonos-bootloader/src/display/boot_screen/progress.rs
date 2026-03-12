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
 * Boot Progress Display - Cyan neon theme.
 */

use crate::display::constants::*;
use crate::display::font::draw_string;
use crate::display::gop::{fill_rect, get_dimensions};
use core::sync::atomic::{AtomicU32, Ordering};

static ANIMATION_FRAME: AtomicU32 = AtomicU32::new(0);

pub fn draw_boot_progress(progress: u32, total: u32) {
    let (width, height) = get_dimensions();
    if width == 0 {
        return;
    }

    let bar_w = width - 80;
    let bar_x = 40;
    let bar_y = height - 32;

    fill_rect(bar_x, bar_y, bar_w, 1, COLOR_GLASS_BORDER);
    fill_rect(bar_x, bar_y + 7, bar_w, 1, COLOR_GLASS_BORDER);

    if total > 0 && progress > 0 {
        let fill = (bar_w * progress.min(total)) / total;
        fill_rect(bar_x, bar_y + 1, fill, 6, COLOR_ACCENT);
    }
}

pub fn show_handoff_message() {
    let (_, height) = get_dimensions();
    if height == 0 {
        return;
    }

    draw_string(48, height - 56, b"Transferring to kernel...", COLOR_SUCCESS);
}

pub fn show_error_screen(error: &[u8]) {
    let (width, height) = get_dimensions();
    if width == 0 {
        return;
    }

    let panel_w = 600;
    let panel_h = 100;
    let panel_x = (width - panel_w) / 2;
    let panel_y = (height - panel_h) / 2;

    fill_rect(panel_x, panel_y, panel_w, panel_h, COLOR_ERROR_BG);
    fill_rect(panel_x, panel_y, panel_w, 2, COLOR_ERROR);
    draw_string(panel_x + 20, panel_y + 24, b"BOOT FAILED", COLOR_TEXT_WHITE);
    draw_string(panel_x + 20, panel_y + 50, error, COLOR_TEXT_WHITE);
}

pub fn tick_animation() {
    let _ = ANIMATION_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub fn reset_animation() {
    ANIMATION_FRAME.store(0, Ordering::Release);
}

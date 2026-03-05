// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::backgrounds::{get_background, next_background, prev_background};
use super::render::{draw_string, draw_toggle};
use super::state::*;
use core::sync::atomic::Ordering;

pub(super) fn draw(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y, b"Dark Theme", COLOR_TEXT_WHITE);
    draw_string(x + 15, y + 18, b"Use dark color scheme", 0xFF7D8590);
    draw_toggle(x + w - 70, y - 5, is_dark_theme());

    draw_string(x + 15, y + 50, b"Auto-Wipe on Shutdown", COLOR_TEXT_WHITE);
    draw_string(x + 15, y + 68, b"Securely wipe RAM on power off", 0xFF7D8590);
    let wipe_enabled = SETTING_AUTO_WIPE.load(Ordering::Relaxed);
    draw_toggle(x + w - 70, y + 45, wipe_enabled);

    draw_string(x + 15, y + 100, b"Desktop Background", COLOR_ACCENT);

    let bg = get_background();
    let bg_name = bg.name();

    fill_rect(x + 15, y + 120, w - 30, 36, 0xFF1A1F26);

    fill_rect(x + 20, y + 125, 26, 26, 0xFF2D333B);
    draw_string(x + 28, y + 130, b"<", COLOR_TEXT_WHITE);

    draw_bg_name(x + 60, y + 131, bg_name);

    fill_rect(x + w - 46, y + 125, 26, 26, 0xFF2D333B);
    draw_string(x + w - 38, y + 130, b">", COLOR_TEXT_WHITE);

    draw_string(x + 15, y + 170, b"System Information", COLOR_ACCENT);

    fill_rect(x + 15, y + 190, w - 30, 100, 0xFF1A1F26);

    draw_string(x + 25, y + 200, b"OS:", 0xFF7D8590);
    draw_string(x + 80, y + 200, b"N\xd8NOS ZeroState v1.0.0", COLOR_TEXT_WHITE);

    draw_string(x + 25, y + 218, b"Arch:", 0xFF7D8590);
    draw_string(x + 80, y + 218, b"x86_64", COLOR_TEXT_WHITE);

    draw_string(x + 25, y + 236, b"Memory:", 0xFF7D8590);
    draw_string(x + 80, y + 236, b"RAM-only (volatile)", COLOR_TEXT_WHITE);

    draw_string(x + 25, y + 254, b"Boot:", 0xFF7D8590);
    draw_string(x + 80, y + 254, b"UEFI Secure Boot", COLOR_TEXT_WHITE);

    draw_string(x + 25, y + 272, b"Kernel:", 0xFF7D8590);
    draw_string(x + 80, y + 272, b"Ed25519 Verified", COLOR_GREEN);
}

fn draw_bg_name(x: u32, y: u32, name: &str) {
    for (i, ch) in name.bytes().enumerate() {
        crate::graphics::font::draw_char(x + (i as u32) * 8, y, ch, COLOR_TEXT_WHITE);
    }
}

static BACKGROUND_CHANGED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn take_background_changed() -> bool {
    BACKGROUND_CHANGED.swap(false, Ordering::Relaxed)
}

pub(super) fn handle_click(content_x: u32, content_y: u32, content_w: u32, click_x: i32, click_y: i32) -> bool {
    let toggle_x = content_x + content_w - 70;

    let dark_y = content_y + 45 - 5;
    if click_x >= toggle_x as i32 && click_x < (toggle_x + 50) as i32 {
        if click_y >= dark_y as i32 && click_y < (dark_y + 26) as i32 {
            toggle_setting(&SETTING_DARK_THEME);
            return true;
        }
    }

    let wipe_y = content_y + 45 + 45;
    if click_x >= toggle_x as i32 && click_x < (toggle_x + 50) as i32 {
        if click_y >= wipe_y as i32 && click_y < (wipe_y + 26) as i32 {
            toggle_setting(&SETTING_AUTO_WIPE);
            return true;
        }
    }

    let bg_button_y = content_y + 45 + 80;

    let prev_x = content_x + 20;
    if click_x >= prev_x as i32 && click_x < (prev_x + 26) as i32 {
        if click_y >= bg_button_y as i32 && click_y < (bg_button_y + 26) as i32 {
            prev_background();
            BACKGROUND_CHANGED.store(true, Ordering::Relaxed);
            return true;
        }
    }

    let next_x = content_x + content_w - 46;
    if click_x >= next_x as i32 && click_x < (next_x + 26) as i32 {
        if click_y >= bg_button_y as i32 && click_y < (bg_button_y + 26) as i32 {
            next_background();
            BACKGROUND_CHANGED.store(true, Ordering::Relaxed);
            return true;
        }
    }

    false
}

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
use crate::sys::settings as sys_settings;
use super::render::{draw_string, draw_toggle};
use super::state::*;
use core::sync::atomic::Ordering;

pub(super) fn draw(x: u32, y: u32, w: u32) {
    let brightness = sys_settings::brightness();
    draw_string(x + 15, y, b"Brightness", COLOR_TEXT_WHITE);
    draw_slider(x + 15, y + 20, w - 30, brightness, 100);

    let sensitivity = sys_settings::mouse_sensitivity();
    draw_string(x + 15, y + 55, b"Mouse Speed", COLOR_TEXT_WHITE);
    draw_slider(x + 15, y + 75, w - 30, sensitivity, 10);

    draw_string(x + 15, y + 110, b"Sound", COLOR_TEXT_WHITE);
    draw_toggle(x + w - 70, y + 105, sys_settings::sound_enabled());

    draw_string(x + 15, y + 150, b"Keyboard Layout", COLOR_TEXT_WHITE);
    let layouts: [&[u8]; 4] = [b"US", b"UK", b"DE", b"FR"];
    let current_layout = sys_settings::keyboard_layout() as usize;
    let btn_w = 50u32;
    for (i, name) in layouts.iter().enumerate() {
        let bx = x + 15 + (i as u32) * (btn_w + 8);
        let by = y + 170;
        let is_sel = current_layout == i;
        let color = if is_sel { COLOR_ACCENT } else { 0xFF2D333B };
        fill_rect(bx, by, btn_w, 26, color);
        draw_string(bx + 16, by + 7, name, if is_sel { 0xFF0D1117 } else { COLOR_TEXT_WHITE });
    }

    draw_string(x + 15, y + 210, b"Dark Theme", COLOR_TEXT_WHITE);
    draw_toggle(x + w - 70, y + 205, is_dark_theme());

    draw_string(x + 15, y + 250, b"Desktop Background", COLOR_ACCENT);
    let bg = get_background();
    fill_rect(x + 15, y + 270, w - 30, 36, 0xFF1A1F26);
    fill_rect(x + 20, y + 275, 26, 26, 0xFF2D333B);
    draw_string(x + 28, y + 280, b"<", COLOR_TEXT_WHITE);
    draw_bg_name(x + 60, y + 281, bg.name());
    fill_rect(x + w - 46, y + 275, 26, 26, 0xFF2D333B);
    draw_string(x + w - 38, y + 280, b">", COLOR_TEXT_WHITE);

    draw_string(x + 15, y + 320, b"System Information", COLOR_ACCENT);
    fill_rect(x + 15, y + 340, w - 30, 80, 0xFF1A1F26);
    draw_string(x + 25, y + 350, b"OS:", 0xFF7D8590);
    draw_string(x + 80, y + 350, b"N\xd8NOS ZeroState v0.8.3", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 368, b"Arch:", 0xFF7D8590);
    draw_string(x + 80, y + 368, b"x86_64 UEFI", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 386, b"Memory:", 0xFF7D8590);
    draw_string(x + 80, y + 386, b"RAM-only (volatile)", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 404, b"Kernel:", 0xFF7D8590);
    draw_string(x + 80, y + 404, b"Ed25519 Verified", COLOR_GREEN);
}

fn draw_slider(x: u32, y: u32, w: u32, value: u8, max: u8) {
    fill_rect(x, y + 8, w, 8, 0xFF374151);
    let fill_w = ((value as u32) * w) / (max as u32);
    fill_rect(x, y + 8, fill_w, 8, COLOR_ACCENT);
    let knob_x = x + fill_w;
    fill_rect(knob_x.saturating_sub(6), y + 4, 12, 16, 0xFFFFFFFF);
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

    let bright_y = content_y + 20;
    if click_y >= bright_y as i32 && click_y < (bright_y + 24) as i32 {
        let rel_x = click_x - content_x as i32 - 15;
        if rel_x >= 0 && rel_x < (content_w - 30) as i32 {
            let new_val = ((rel_x as u32) * 100 / (content_w - 30)).min(100) as u8;
            sys_settings::set_brightness(new_val);
            return true;
        }
    }

    let sens_y = content_y + 75;
    if click_y >= sens_y as i32 && click_y < (sens_y + 24) as i32 {
        let rel_x = click_x - content_x as i32 - 15;
        if rel_x >= 0 && rel_x < (content_w - 30) as i32 {
            let new_val = (((rel_x as u32) * 10 / (content_w - 30)) + 1).min(10) as u8;
            sys_settings::set_mouse_sensitivity(new_val);
            return true;
        }
    }

    let sound_y = content_y + 105;
    if click_x >= toggle_x as i32 && click_x < (toggle_x + 50) as i32 {
        if click_y >= sound_y as i32 && click_y < (sound_y + 26) as i32 {
            sys_settings::set_sound_enabled(!sys_settings::sound_enabled());
            return true;
        }
    }

    let layout_y = content_y + 170;
    if click_y >= layout_y as i32 && click_y < (layout_y + 26) as i32 {
        let rel_x = click_x - content_x as i32 - 15;
        if rel_x >= 0 {
            let btn_idx = (rel_x / 58) as u8;
            if btn_idx < 4 {
                sys_settings::set_keyboard_layout(btn_idx);
                return true;
            }
        }
    }

    let dark_y = content_y + 205;
    if click_x >= toggle_x as i32 && click_x < (toggle_x + 50) as i32 {
        if click_y >= dark_y as i32 && click_y < (dark_y + 26) as i32 {
            toggle_setting(&SETTING_DARK_THEME);
            return true;
        }
    }

    let bg_button_y = content_y + 275;
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

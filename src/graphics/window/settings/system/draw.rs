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

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::sys::settings as sys_settings;
use crate::graphics::window::settings::render::{draw_string, draw_toggle};
use crate::graphics::window::settings::state::is_dark_theme;
use super::slider::draw_slider;
use super::info::draw_system_info;
use super::timezone::{draw_timezone, draw_screen_timeout};

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    draw_brightness(x, y, w);
    draw_mouse_speed(x, y, w);
    draw_sound_toggle(x, y, w);
    draw_keyboard_layout(x, y, w);
    draw_dark_theme(x, y, w);
    draw_system_info(x, y, w);
    draw_timezone(x, y, w);
    draw_screen_timeout(x, y, w);
}

fn draw_brightness(x: u32, y: u32, w: u32) {
    let brightness = sys_settings::brightness();
    draw_string(x + 15, y, b"Brightness", COLOR_TEXT_WHITE);
    draw_slider(x + 15, y + 18, w - 30, brightness, 100);
}

fn draw_mouse_speed(x: u32, y: u32, w: u32) {
    let sensitivity = sys_settings::mouse_sensitivity();
    draw_string(x + 15, y + 48, b"Mouse Speed", COLOR_TEXT_WHITE);
    draw_slider(x + 15, y + 66, w - 30, sensitivity, 10);
}

fn draw_sound_toggle(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 96, b"Sound", COLOR_TEXT_WHITE);
    draw_toggle(x + w - 70, y + 92, sys_settings::sound_enabled());
}

fn draw_keyboard_layout(x: u32, y: u32, _w: u32) {
    draw_string(x + 15, y + 125, b"Keyboard Layout", COLOR_TEXT_WHITE);
    let row1: [&[u8]; 5] = [b"US", b"DVK", b"FR", b"COL", b"DE"];
    let row2: [&[u8]; 4] = [b"UK", b"ES", b"IT", b"PT"];
    let current_layout = sys_settings::keyboard_layout() as usize;
    let btn_w = 50u32;
    for (i, name) in row1.iter().enumerate() {
        let bx = x + 15 + (i as u32) * (btn_w + 4);
        let is_sel = current_layout == i;
        let color = if is_sel { COLOR_ACCENT } else { 0xFF2D333B };
        fill_rect(bx, y + 143, btn_w, 22, color);
        let txt = if is_sel { 0xFF0D1117 } else { COLOR_TEXT_WHITE };
        draw_string(bx + 10, y + 147, name, txt);
    }
    for (i, name) in row2.iter().enumerate() {
        let bx = x + 15 + (i as u32) * (btn_w + 4);
        let is_sel = current_layout == (i + 5);
        let color = if is_sel { COLOR_ACCENT } else { 0xFF2D333B };
        fill_rect(bx, y + 168, btn_w, 22, color);
        let txt = if is_sel { 0xFF0D1117 } else { COLOR_TEXT_WHITE };
        draw_string(bx + 10, y + 172, name, txt);
    }
}

fn draw_dark_theme(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 200, b"Dark Theme", COLOR_TEXT_WHITE);
    draw_toggle(x + w - 70, y + 196, is_dark_theme());
}

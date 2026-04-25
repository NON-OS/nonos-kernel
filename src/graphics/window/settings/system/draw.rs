// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::slider::draw_slider;
use super::timezone::{draw_screen_timeout, draw_timezone};
use crate::graphics::framebuffer::fill_rounded_rect;
use crate::graphics::window::settings::render::{draw_string, draw_toggle};
use crate::graphics::window::settings::state::is_dark_theme;
use crate::sys::settings as sys_settings;

const BG_CARD: u32 = 0xFF161B22;
const BG_BTN: u32 = 0xFF21262D;
const BG_BTN_SEL: u32 = 0xFF1F6FEB;
const TEXT: u32 = 0xFFE6EDF3;
const TEXT_DIM: u32 = 0xFF7D8590;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    fill_rounded_rect(x + 16, y, w - 32, 120, 8, BG_CARD);
    draw_string(x + 28, y + 12, b"Display", TEXT);
    draw_string(x + 28, y + 36, b"Brightness", TEXT_DIM);
    draw_slider(x + 28, y + 52, w - 72, sys_settings::brightness(), 100);
    draw_string(x + 28, y + 78, b"Mouse Speed", TEXT_DIM);
    draw_slider(x + 28, y + 94, w - 72, sys_settings::mouse_sensitivity(), 10);
    fill_rounded_rect(x + 16, y + 130, w - 32, 110, 8, BG_CARD);
    draw_string(x + 28, y + 142, b"Sound", TEXT);
    draw_toggle(x + w - 72, y + 138, sys_settings::sound_enabled());
    draw_string(x + 28, y + 170, b"Notifications", TEXT);
    draw_toggle(x + w - 72, y + 166, sys_settings::notifications_enabled());
    draw_string(x + 28, y + 198, b"Dark Theme", TEXT);
    draw_toggle(x + w - 72, y + 194, is_dark_theme());
    fill_rounded_rect(x + 16, y + 250, w - 32, 70, 8, BG_CARD);
    draw_string(x + 28, y + 262, b"Keyboard", TEXT);
    let layouts: [&[u8]; 5] = [b"US", b"DVK", b"DE", b"FR", b"UK"];
    let current = sys_settings::keyboard_layout() as usize;
    let bw = 48u32;
    for (i, name) in layouts.iter().enumerate() {
        let bx = x + 28 + (i as u32) * (bw + 4);
        let sel = current == i;
        fill_rounded_rect(bx, y + 282, bw, 26, 4, if sel { BG_BTN_SEL } else { BG_BTN });
        let tc = if sel { TEXT } else { TEXT_DIM };
        let tx = bx + (bw - (name.len() as u32 * 8)) / 2;
        draw_string(tx, y + 288, name, tc);
    }
    draw_timezone(x, y, w);
    draw_screen_timeout(x, y, w);
    draw_language(x, y, w);
}

fn draw_language(x: u32, y: u32, w: u32) {
    fill_rounded_rect(x + 16, y + 400, w - 32, 70, 8, BG_CARD);
    draw_string(x + 28, y + 412, b"Language", TEXT);
    let langs: [&[u8]; 6] = [b"EN", b"ES", b"FR", b"DE", b"ZH", b"JA"];
    let current = crate::locale::get_lang() as usize;
    let bw = 36u32;
    for (i, name) in langs.iter().enumerate() {
        let bx = x + 28 + (i as u32) * (bw + 4);
        let sel = current == i;
        fill_rounded_rect(bx, y + 432, bw, 26, 4, if sel { BG_BTN_SEL } else { BG_BTN });
        let tc = if sel { TEXT } else { TEXT_DIM };
        let tx = bx + (bw - (name.len() as u32 * 8)) / 2;
        draw_string(tx, y + 438, name, tc);
    }
}

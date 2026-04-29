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

use super::shortcuts::SHORTCUTS;
use super::state::get_state;
use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::fill_rect;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 44;
const LABEL_X: u32 = 24;

pub fn draw(x: u32, y: u32, w: u32, _h: u32) {
    let state = get_state();
    draw_header(x, y);
    draw_layout_row(x, y, w, &state);
    draw_repeat_rate_row(x, y, &state);
    draw_repeat_delay_row(x, y, &state);
    draw_toggles(x, y, &state);
    draw_shortcuts(x, y);
}

fn draw_header(x: u32, y: u32) {
    draw_text(x + LABEL_X, y + 24, b"Keyboard", TEXT_PRIMARY);
    draw_text(x + LABEL_X, y + 48, b"Layout, repeat, and shortcuts", TEXT_SECONDARY);
}

fn draw_layout_row(x: u32, y: u32, w: u32, s: &super::state::KeyboardState) {
    let sy = y + SECTION_Y;
    draw_text(x + LABEL_X, sy, b"Layout", TEXT_PRIMARY);
    fill_rect(x + w - 160, sy - 4, 120, 28, BG_INPUT);
    draw_text(x + w - 152, sy, s.layout_name().as_bytes(), TEXT_PRIMARY);
}

fn draw_repeat_rate_row(x: u32, y: u32, s: &super::state::KeyboardState) {
    let sy = y + SECTION_Y + ROW_HEIGHT;
    draw_text(x + LABEL_X, sy, b"Key Repeat Rate", TEXT_PRIMARY);
    let bar_x = x + 180;
    let bar_w = 160u32;
    let fill_w = (bar_w * s.repeat_rate as u32) / 100;
    fill_rect(bar_x, sy + 2, bar_w, 12, BG_INPUT);
    fill_rect(bar_x, sy + 2, fill_w, 12, ACCENT);
}

fn draw_repeat_delay_row(x: u32, y: u32, s: &super::state::KeyboardState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 2;
    draw_text(x + LABEL_X, sy, b"Delay Until Repeat", TEXT_PRIMARY);
    let bar_x = x + 180;
    let bar_w = 160u32;
    let fill_w = (bar_w * s.repeat_delay as u32) / 100;
    fill_rect(bar_x, sy + 2, bar_w, 12, BG_INPUT);
    fill_rect(bar_x, sy + 2, fill_w, 12, ACCENT);
}

fn draw_toggles(x: u32, y: u32, s: &super::state::KeyboardState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 3;
    draw_text(x + LABEL_X, sy, b"Caps Lock LED", TEXT_PRIMARY);
    let led_status = if s.caps_lock_led { b"On" as &[u8] } else { b"Off" };
    draw_text(x + 180, sy, led_status, TEXT_SECONDARY);
    let sy2 = y + SECTION_Y + ROW_HEIGHT * 4;
    draw_text(x + LABEL_X, sy2, b"Standard Fn Keys", TEXT_PRIMARY);
    let fn_status = if s.fn_key_standard { b"On" as &[u8] } else { b"Off" };
    draw_text(x + 180, sy2, fn_status, TEXT_SECONDARY);
}

fn draw_shortcuts(x: u32, y: u32) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 5 + 12;
    draw_text(x + LABEL_X, sy, b"Keyboard Shortcuts", TEXT_PRIMARY);
    for (i, shortcut) in SHORTCUTS.iter().take(6).enumerate() {
        let row_y = sy + 28 + (i as u32) * 24;
        draw_text(x + LABEL_X, row_y, shortcut.name.as_bytes(), TEXT_SECONDARY);
        draw_text(x + 200, row_y, shortcut.keys.as_bytes(), ACCENT);
    }
}

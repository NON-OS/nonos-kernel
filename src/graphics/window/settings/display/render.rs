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

use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::design_system::colors::*;
use super::state::get_state;
use super::scaling;

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 48;
const LABEL_X: u32 = 24;

pub fn draw(x: u32, y: u32, w: u32, _h: u32) {
    let state = get_state();
    draw_header(x, y);
    draw_resolution_section(x, y, w, &state);
    draw_scaling_section(x, y, w, &state);
    draw_brightness_section(x, y, &state);
    draw_night_shift_section(x, y, &state);
}

fn draw_header(x: u32, y: u32) {
    draw_text(x + LABEL_X, y + 24, b"Display", TEXT_PRIMARY);
    draw_text(x + LABEL_X, y + 48, b"Configure resolution, scaling, and color", TEXT_SECONDARY);
}

fn draw_resolution_section(x: u32, y: u32, w: u32, state: &super::state::DisplayState) {
    let sy = y + SECTION_Y;
    draw_text(x + LABEL_X, sy, b"Resolution", TEXT_PRIMARY);
    let res_str = state.resolution_str();
    fill_rect(x + w - 200, sy - 4, 160, 28, BG_INPUT);
    draw_text(x + w - 192, sy, res_str.as_bytes(), TEXT_PRIMARY);
}

fn draw_scaling_section(x: u32, y: u32, w: u32, state: &super::state::DisplayState) {
    let sy = y + SECTION_Y + ROW_HEIGHT;
    draw_text(x + LABEL_X, sy, b"Scaling", TEXT_PRIMARY);
    let scale_str = scaling::scale_label(state.scale_factor);
    fill_rect(x + w - 200, sy - 4, 160, 28, BG_INPUT);
    draw_text(x + w - 192, sy, scale_str.as_bytes(), TEXT_PRIMARY);
}

fn draw_brightness_section(x: u32, y: u32, state: &super::state::DisplayState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 2;
    draw_text(x + LABEL_X, sy, b"Brightness", TEXT_PRIMARY);
    let bar_x = x + 150;
    let bar_w = 200u32;
    let fill_w = (bar_w * state.brightness as u32) / 100;
    fill_rect(bar_x, sy + 2, bar_w, 12, BG_INPUT);
    fill_rect(bar_x, sy + 2, fill_w, 12, ACCENT);
}

fn draw_night_shift_section(x: u32, y: u32, state: &super::state::DisplayState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 3;
    draw_text(x + LABEL_X, sy, b"Night Shift", TEXT_PRIMARY);
    let status = if state.night_shift_enabled { b"On" as &[u8] } else { b"Off" };
    draw_text(x + 150, sy, status, TEXT_SECONDARY);
}

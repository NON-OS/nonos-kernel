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

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 44;
const LABEL_X: u32 = 24;
const SLIDER_X: u32 = 200;
const SLIDER_W: u32 = 160;

pub fn draw(x: u32, y: u32, _w: u32, _h: u32) {
    let state = get_state();
    draw_header(x, y);
    draw_tracking_speed(x, y, &state);
    draw_scroll_speed(x, y, &state);
    draw_double_click(x, y, &state);
    draw_toggles(x, y, &state);
}

fn draw_header(x: u32, y: u32) {
    draw_text(x + LABEL_X, y + 24, b"Mouse & Trackpad", TEXT_PRIMARY);
    draw_text(x + LABEL_X, y + 48, b"Pointer speed and scrolling", TEXT_SECONDARY);
}

fn draw_slider(x: u32, y: u32, val: u8) {
    let fill_w = (SLIDER_W * val as u32) / 100;
    fill_rect(x + SLIDER_X, y + 2, SLIDER_W, 12, BG_INPUT);
    fill_rect(x + SLIDER_X, y + 2, fill_w, 12, ACCENT);
}

fn draw_tracking_speed(x: u32, y: u32, s: &super::state::MouseState) {
    let sy = y + SECTION_Y;
    draw_text(x + LABEL_X, sy, b"Tracking Speed", TEXT_PRIMARY);
    draw_slider(x, sy, s.tracking_speed);
}

fn draw_scroll_speed(x: u32, y: u32, s: &super::state::MouseState) {
    let sy = y + SECTION_Y + ROW_HEIGHT;
    draw_text(x + LABEL_X, sy, b"Scroll Speed", TEXT_PRIMARY);
    draw_slider(x, sy, s.scroll_speed);
}

fn draw_double_click(x: u32, y: u32, s: &super::state::MouseState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 2;
    draw_text(x + LABEL_X, sy, b"Double-Click Speed", TEXT_PRIMARY);
    draw_slider(x, sy, s.double_click_speed);
}

fn draw_toggles(x: u32, y: u32, s: &super::state::MouseState) {
    let sy = y + SECTION_Y + ROW_HEIGHT * 3;
    draw_text(x + LABEL_X, sy, b"Natural Scrolling", TEXT_PRIMARY);
    let ns = if s.natural_scroll { b"On" as &[u8] } else { b"Off" };
    draw_text(x + SLIDER_X, sy, ns, TEXT_SECONDARY);
    let sy2 = y + SECTION_Y + ROW_HEIGHT * 4;
    draw_text(x + LABEL_X, sy2, b"Pointer Acceleration", TEXT_PRIMARY);
    let pa = if s.pointer_acceleration { b"On" as &[u8] } else { b"Off" };
    draw_text(x + SLIDER_X, sy2, pa, TEXT_SECONDARY);
}

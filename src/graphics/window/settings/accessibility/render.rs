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
use super::{state::get_state, vision};

const SECTION_Y: u32 = 80;
const ROW_HEIGHT: u32 = 40;
const LABEL_X: u32 = 24;
const TOGGLE_X: u32 = 280;

pub fn draw(x: u32, y: u32, w: u32, _h: u32) {
    let state = get_state();
    draw_header(x, y);
    draw_display_section(x, y, w, &state);
    draw_vision_toggles(x, y, &state);
    draw_motor_section(x, y, &state);
}

fn draw_header(x: u32, y: u32) {
    draw_text(x + LABEL_X, y + 24, b"Accessibility", TEXT_PRIMARY);
    draw_text(x + LABEL_X, y + 48, b"Vision, hearing, and motor settings", TEXT_SECONDARY);
}

fn draw_display_section(x: u32, y: u32, w: u32, s: &super::state::AccessibilityState) {
    let sy = y + SECTION_Y;
    draw_text(x + LABEL_X, sy, b"Text Size", TEXT_PRIMARY);
    let font_label = vision::font_size_label(s.font_size_idx);
    fill_rect(x + w - 180, sy - 4, 140, 28, BG_INPUT);
    draw_text(x + w - 172, sy, font_label.as_bytes(), TEXT_PRIMARY);
    let sy2 = y + SECTION_Y + ROW_HEIGHT;
    draw_text(x + LABEL_X, sy2, b"Cursor Size", TEXT_PRIMARY);
    let cursor_label = vision::cursor_size_label(s.cursor_size_idx);
    fill_rect(x + w - 180, sy2 - 4, 140, 28, BG_INPUT);
    draw_text(x + w - 172, sy2, cursor_label.as_bytes(), TEXT_PRIMARY);
}

fn draw_toggle(x: u32, y: u32, label: &[u8], enabled: bool) {
    draw_text(x + LABEL_X, y, label, TEXT_PRIMARY);
    let status = if enabled { b"On" as &[u8] } else { b"Off" };
    let color = if enabled { SUCCESS } else { TEXT_SECONDARY };
    draw_text(x + TOGGLE_X, y, status, color);
}

fn draw_vision_toggles(x: u32, y: u32, s: &super::state::AccessibilityState) {
    let base = y + SECTION_Y + ROW_HEIGHT * 2;
    draw_toggle(x, base, b"Bold Text", s.bold_text);
    draw_toggle(x, base + ROW_HEIGHT, b"Increase Contrast", s.high_contrast);
    draw_toggle(x, base + ROW_HEIGHT * 2, b"Reduce Motion", s.reduce_motion);
    draw_toggle(x, base + ROW_HEIGHT * 3, b"Reduce Transparency", s.reduce_transparency);
    draw_toggle(x, base + ROW_HEIGHT * 4, b"Invert Colors", s.invert_colors);
}

fn draw_motor_section(x: u32, y: u32, s: &super::state::AccessibilityState) {
    let base = y + SECTION_Y + ROW_HEIGHT * 7;
    draw_toggle(x, base, b"Full Keyboard Access", s.keyboard_navigation);
    draw_toggle(x, base + ROW_HEIGHT, b"Zoom", s.zoom_enabled);
}

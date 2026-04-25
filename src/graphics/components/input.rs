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

use super::{primitives, text};
use crate::graphics::design_system::{borders, colors, spacing};
use crate::graphics::framebuffer::fill_rect;

pub struct InputState {
    pub focused: bool,
    pub error: bool,
    pub cursor_pos: usize,
}

impl Default for InputState {
    fn default() -> Self {
        Self { focused: false, error: false, cursor_pos: 0 }
    }
}

pub fn draw_input(x: u32, y: u32, w: u32, value: &[u8], placeholder: &[u8], state: &InputState) {
    let h = spacing::INPUT_HEIGHT_MD;
    let radius = borders::RADIUS_INPUT;

    primitives::rounded_rect(x, y, w, h, radius, colors::BG_INPUT);

    let border_color = if state.error {
        colors::BORDER_ERROR
    } else if state.focused {
        colors::BORDER_FOCUS
    } else {
        colors::BORDER_DEFAULT
    };
    primitives::rounded_rect_outline(x, y, w, h, radius, 1, border_color);

    let text_x = x + spacing::INPUT_PADDING_X;
    let text_y = y + (h - 16) / 2;

    if value.is_empty() {
        text::draw(text_x, text_y, placeholder, colors::TEXT_PLACEHOLDER);
    } else {
        text::draw(text_x, text_y, value, colors::TEXT_PRIMARY);
    }

    if state.focused {
        let cursor_x = text_x + (state.cursor_pos as u32 * 8);
        fill_rect(cursor_x, y + 8, 2, h - 16, colors::ACCENT);
    }
}

pub fn input_hit_test(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    let h = spacing::INPUT_HEIGHT_MD;
    click_x >= x as i32
        && click_x < (x + w) as i32
        && click_y >= y as i32
        && click_y < (y + h) as i32
}

pub fn cursor_pos_from_click(x: u32, click_x: i32, value_len: usize) -> usize {
    let text_x = x + spacing::INPUT_PADDING_X;
    if click_x <= text_x as i32 {
        return 0;
    }
    let offset = (click_x as u32).saturating_sub(text_x);
    let pos = (offset / 8) as usize;
    pos.min(value_len)
}

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

use crate::graphics::design_system::typography::{CHAR_HEIGHT, CHAR_WIDTH};
use crate::graphics::font::draw_char;

pub fn draw(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * CHAR_WIDTH, y, ch, color);
    }
}

pub fn draw_centered(x: u32, y: u32, width: u32, text: &[u8], color: u32) {
    let text_w = text.len() as u32 * CHAR_WIDTH;
    let start_x = x + width.saturating_sub(text_w) / 2;
    draw(start_x, y, text, color);
}

pub fn draw_right(x: u32, y: u32, width: u32, text: &[u8], color: u32) {
    let text_w = text.len() as u32 * CHAR_WIDTH;
    let start_x = x + width.saturating_sub(text_w);
    draw(start_x, y, text, color);
}

pub fn draw_scaled(x: u32, y: u32, text: &[u8], color: u32, scale: u32) {
    use crate::graphics::font::draw_char_scaled;
    for (i, &ch) in text.iter().enumerate() {
        draw_char_scaled(x + (i as u32) * CHAR_WIDTH * scale, y, ch, color, scale);
    }
}

pub fn draw_truncated(x: u32, y: u32, max_width: u32, text: &[u8], color: u32) {
    let max_chars = (max_width / CHAR_WIDTH) as usize;
    if text.len() <= max_chars {
        draw(x, y, text, color);
    } else if max_chars > 3 {
        draw(x, y, &text[..max_chars - 3], color);
        draw(x + ((max_chars - 3) as u32) * CHAR_WIDTH, y, b"...", color);
    }
}

pub fn measure(text: &[u8]) -> (u32, u32) {
    (text.len() as u32 * CHAR_WIDTH, CHAR_HEIGHT)
}

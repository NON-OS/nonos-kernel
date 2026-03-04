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

use crate::graphics::framebuffer::{put_pixel, dimensions};
use super::bitmap::{CHAR_WIDTH, CHAR_HEIGHT, get_char_bitmap};

pub fn draw_char(x: u32, y: u32, ch: u8, color: u32) {
    let bitmap = get_char_bitmap(ch);
    for row in 0..CHAR_HEIGHT {
        let bits = bitmap[row as usize];
        for col in 0..CHAR_WIDTH {
            if (bits >> (7 - col)) & 1 == 1 {
                put_pixel(x + col, y + row, color);
            }
        }
    }
}

pub fn draw_text(x: u32, y: u32, text: &[u8], color: u32) {
    let mut cx = x;
    for &ch in text {
        if ch == b'\n' {
            continue;
        }
        draw_char(cx, y, ch, color);
        cx += CHAR_WIDTH;
    }
}

pub fn draw_text_centered(y: u32, text: &[u8], color: u32) {
    let (w, _) = dimensions();
    let text_w = (text.len() as u32) * CHAR_WIDTH;
    let x = (w / 2).saturating_sub(text_w / 2);
    draw_text(x, y, text, color);
}

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

use core::sync::atomic::Ordering;
use crate::display::{Framebuffer, font, fill_rect, write_pixel};
use super::state::{DISPLAY_ENABLED, LOG_Y, CHAR_HEIGHT, LEFT_MARGIN, BG_COLOR};

pub(super) fn write_line(_tag: &str, msg: &str, color: u32) {
    if !DISPLAY_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let y = advance_line();
    clear_line(y);
    let mut x = LEFT_MARGIN;
    x = render_str(x, y, "[+] ", color);
    let _ = render_str(x, y, msg, color);
}

fn advance_line() -> u32 {
    let y = LOG_Y.fetch_add(CHAR_HEIGHT, Ordering::Relaxed);
    if let Ok(info) = Framebuffer::info() {
        if y + CHAR_HEIGHT >= info.height - 40 {
            LOG_Y.store(24, Ordering::Relaxed);
            return 24;
        }
    }
    y
}

fn clear_line(y: u32) {
    if let Ok(info) = Framebuffer::info() {
        let _ = fill_rect(0, y, info.width, CHAR_HEIGHT, BG_COLOR);
    }
}

fn render_str(mut x: u32, y: u32, s: &str, color: u32) -> u32 {
    for c in s.chars() {
        render_char(x, y, c, color);
        x += 8;
    }
    x
}

fn render_char(x: u32, y: u32, c: char, color: u32) {
    let glyph = font::get_glyph(c);
    for row in 0..16u32 {
        let bits = glyph[row as usize];
        for col in 0..8u32 {
            if (bits >> (7 - col)) & 1 != 0 {
                let _ = write_pixel(x + col, y + row, color);
            }
        }
    }
}

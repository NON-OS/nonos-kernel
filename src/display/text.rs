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

use super::error::DisplayError;
use super::font;
use super::framebuffer::{clear, write_pixel, Framebuffer};
use core::sync::atomic::{AtomicU32, Ordering};

const CHAR_WIDTH: u32 = 8;
const CHAR_HEIGHT: u32 = 16;

static CURSOR_X: AtomicU32 = AtomicU32::new(0);
static CURSOR_Y: AtomicU32 = AtomicU32::new(0);

pub fn write_char(c: char) -> Result<(), DisplayError> {
    let info = Framebuffer::info()?;
    let mut x = CURSOR_X.load(Ordering::Relaxed);
    let mut y = CURSOR_Y.load(Ordering::Relaxed);
    match c {
        '\n' => {
            x = 0;
            y += CHAR_HEIGHT;
        }
        '\r' => {
            x = 0;
        }
        _ => {
            render_char(x, y, c, 0xFFFFFF)?;
            x += CHAR_WIDTH;
        }
    }
    let max_x = info.width / CHAR_WIDTH * CHAR_WIDTH;
    let max_y = info.height / CHAR_HEIGHT * CHAR_HEIGHT;
    if x >= max_x {
        x = 0;
        y += CHAR_HEIGHT;
    }
    if y >= max_y {
        y = 0;
    }
    CURSOR_X.store(x, Ordering::Relaxed);
    CURSOR_Y.store(y, Ordering::Relaxed);
    Ok(())
}

pub fn write_string(s: &str) -> Result<(), DisplayError> {
    for c in s.chars() {
        write_char(c)?;
    }
    Ok(())
}

pub fn clear_screen() -> Result<(), DisplayError> {
    clear(0x000000)?;
    CURSOR_X.store(0, Ordering::Relaxed);
    CURSOR_Y.store(0, Ordering::Relaxed);
    Ok(())
}

pub fn set_cursor_pos(x: u32, y: u32) {
    CURSOR_X.store(x, Ordering::Relaxed);
    CURSOR_Y.store(y, Ordering::Relaxed);
}

fn render_char(x: u32, y: u32, c: char, color: u32) -> Result<(), DisplayError> {
    let glyph = font::get_glyph(c);
    for row in 0..CHAR_HEIGHT {
        let bits = glyph[row as usize];
        for col in 0..CHAR_WIDTH {
            if (bits >> (7 - col)) & 1 != 0 {
                write_pixel(x + col, y + row, color)?;
            }
        }
    }
    Ok(())
}

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

use crate::graphics::framebuffer::{put_pixel, get_pixel, dimensions, COLOR_TEXT_WHITE};
use super::bitmap::{CURSOR_WIDTH, CURSOR_HEIGHT, CURSOR_BITMAP, CURSOR_MASK};
use super::state::{SAVED_PIXELS, get_saved_position, set_saved_position, clear_saved_position, is_visible, set_visible};

fn save_under_cursor(x: i32, y: i32) {
    let (w, h) = dimensions();

    for row in 0..CURSOR_HEIGHT {
        for col in 0..CURSOR_WIDTH {
            let px = x + col as i32;
            let py = y + row as i32;
            let idx = (row * CURSOR_WIDTH + col) as usize;

            // SAFETY: Single-threaded cursor access, bounds checked
            unsafe {
                if px >= 0 && px < w as i32 && py >= 0 && py < h as i32 {
                    SAVED_PIXELS[idx] = get_pixel(px as u32, py as u32);
                } else {
                    SAVED_PIXELS[idx] = 0;
                }
            }
        }
    }

    set_saved_position(x, y);
}

fn restore_under_cursor() {
    let (saved_x, saved_y) = get_saved_position();

    if saved_x < 0 || saved_y < 0 {
        return;
    }

    let (w, h) = dimensions();

    for row in 0..CURSOR_HEIGHT {
        for col in 0..CURSOR_WIDTH {
            let px = saved_x + col as i32;
            let py = saved_y + row as i32;
            let idx = (row * CURSOR_WIDTH + col) as usize;

            let bit_pos = 15 - col;
            let mask = CURSOR_MASK[row as usize];
            if (mask >> bit_pos) & 1 == 1 {
                if px >= 0 && px < w as i32 && py >= 0 && py < h as i32 {
                    // SAFETY: Single-threaded cursor access, bounds checked
                    unsafe {
                        put_pixel(px as u32, py as u32, SAVED_PIXELS[idx]);
                    }
                }
            }
        }
    }

    clear_saved_position();
}

pub fn draw(x: i32, y: i32) {
    if is_visible() {
        restore_under_cursor();
    }

    save_under_cursor(x, y);

    let (w, h) = dimensions();

    for row in 0..CURSOR_HEIGHT {
        let py = y + row as i32;
        if py < 0 || py >= h as i32 {
            continue;
        }

        let bits = CURSOR_BITMAP[row as usize];
        let mask = CURSOR_MASK[row as usize];

        for col in 0..CURSOR_WIDTH {
            let px = x + col as i32;
            if px < 0 || px >= w as i32 {
                continue;
            }

            let bit_pos = 15 - col;
            if (mask >> bit_pos) & 1 == 1 {
                let color = if (bits >> bit_pos) & 1 == 1 {
                    COLOR_TEXT_WHITE
                } else {
                    0xFF000000
                };
                put_pixel(px as u32, py as u32, color);
            }
        }
    }

    set_visible(true);
}

pub fn erase() {
    if is_visible() {
        restore_under_cursor();
        set_visible(false);
    }
}

pub fn hide() {
    erase();
}

pub fn show(x: i32, y: i32) {
    draw(x, y);
}

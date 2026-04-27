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

use super::state::{CHAR_HEIGHT, DISPLAY_ENABLED, LEFT_MARGIN, LOG_Y};
use crate::display::{font, write_pixel};
use core::sync::atomic::{AtomicU32, Ordering};

const MAX_MSG_LEN: usize = 80;
const SCREEN_HEIGHT: u32 = 1024;
static KERNEL_START_Y: AtomicU32 = AtomicU32::new(0);
static CURRENT_Y: AtomicU32 = AtomicU32::new(0);
static INIT_DONE: AtomicU32 = AtomicU32::new(0);

pub(super) fn write_line(_tag: &str, msg: &str, color: u32) {
    if !DISPLAY_ENABLED.load(Ordering::Acquire) {
        return;
    }

    // Initialize: kernel logs continue from where bootloader ended
    if INIT_DONE.swap(1, Ordering::SeqCst) == 0 {
        let cursor_y = LOG_Y.load(Ordering::Relaxed);
        KERNEL_START_Y.store(cursor_y, Ordering::SeqCst);
        CURRENT_Y.store(cursor_y, Ordering::SeqCst);
    }

    let y = CURRENT_Y.fetch_add(CHAR_HEIGHT, Ordering::SeqCst);

    // Stop if we go off screen
    if y >= SCREEN_HEIGHT - CHAR_HEIGHT {
        return;
    }

    // Draw directly - no clearing, transparent background
    let mut x = LEFT_MARGIN;
    x = render_str(x, y, "[+] ", color);

    let msg_len = msg.len().min(MAX_MSG_LEN);
    let _ = render_str(x, y, &msg[..msg_len], color);

    log_delay();
}

fn log_delay() {
    for _ in 0..300_000 {
        core::hint::spin_loop();
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

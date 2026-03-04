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
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT};
use crate::graphics::font::draw_char;
use super::constants::*;
use super::state::*;

pub fn draw_terminal(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, 0xFF0D1117);

    let char_w = 8u32;
    let char_h = 16u32;
    let padding = 8u32;

    let visible_cols = ((w - padding * 2) / char_w).min(TERM_COLS as u32) as usize;
    let visible_rows = ((h - padding * 2) / char_h).min(TERM_ROWS as u32) as usize;

    // SAFETY: Read-only access to terminal buffer for drawing
    unsafe {
        for row in 0..visible_rows {
            for col in 0..visible_cols {
                let idx = row * TERM_COLS + col;
                if idx < TERM_BUFFER_SIZE {
                    let ch = TERM_BUFFER[idx];
                    let color = TERM_COLORS[idx];
                    let cx = x + padding + (col as u32) * char_w;
                    let cy = y + padding + (row as u32) * char_h;
                    draw_char(cx, cy, ch, color);
                }
            }
        }
    }

    let cursor_x = TERM_CURSOR_X.load(Ordering::Relaxed);
    let cursor_y = TERM_CURSOR_Y.load(Ordering::Relaxed);

    if TERM_CURSOR_VISIBLE.load(Ordering::Relaxed) && cursor_y < visible_rows {
        let cx = x + padding + (cursor_x as u32) * char_w;
        let cy = y + padding + (cursor_y as u32) * char_h;
        fill_rect(cx, cy + char_h - 2, char_w, 2, COLOR_ACCENT);
    }
}

pub fn handle_terminal_click(_win_x: u32, _win_y: u32, _win_w: u32, _win_h: u32, _mx: i32, _my: i32) -> bool {
    false
}

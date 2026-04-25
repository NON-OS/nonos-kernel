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

use super::constants::*;
use super::state::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

const COLOR_BG: u32 = 0xFF0F0F14;
const COLOR_CURSOR: u32 = 0xFF3B82F6;
const HEADER_HEIGHT: u32 = 28;

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub fn draw_terminal(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, HEADER_HEIGHT, 0xFF1A1A1E);
    fill_rect(x, y + HEADER_HEIGHT - 1, w, 1, 0xFF2C2C30);

    draw_string(x + 12, y + 8, b"N\xd8NOS Terminal", 0xFF6B7280);

    let shell_indicator_x = x + w - 80;
    fill_rect(shell_indicator_x, y + 6, 8, 8, 0xFF34D399);
    draw_string(shell_indicator_x + 12, y + 4, b"shell", 0xFF6B7280);

    fill_rect(x, y + HEADER_HEIGHT, w, h - HEADER_HEIGHT, COLOR_BG);

    let char_w = 8u32;
    let char_h = 16u32;
    let padding = 12u32;
    let content_y = y + HEADER_HEIGHT;
    let content_h = h - HEADER_HEIGHT;

    let visible_cols = ((w - padding * 2) / char_w).min(TERM_COLS as u32) as usize;
    let visible_rows = ((content_h - padding * 2) / char_h).min(TERM_ROWS as u32) as usize;

    unsafe {
        for row in 0..visible_rows {
            for col in 0..visible_cols {
                let idx = row * TERM_COLS + col;
                if idx < TERM_BUFFER_SIZE {
                    let ch = TERM_BUFFER[idx];
                    let color = TERM_COLORS[idx];
                    let cx = x + padding + (col as u32) * char_w;
                    let cy = content_y + padding + (row as u32) * char_h;
                    draw_char(cx, cy, ch, color);
                }
            }
        }
    }

    let cursor_x_pos = TERM_CURSOR_X.load(Ordering::Relaxed);
    let cursor_y_pos = TERM_CURSOR_Y.load(Ordering::Relaxed);

    if TERM_CURSOR_VISIBLE.load(Ordering::Relaxed) && cursor_y_pos < visible_rows {
        let blink = (crate::time::timestamp_millis() / 530) % 2 == 0;
        if blink {
            let cx = x + padding + (cursor_x_pos as u32) * char_w;
            let cy = content_y + padding + (cursor_y_pos as u32) * char_h;
            fill_rect(cx, cy, 2, char_h, COLOR_CURSOR);
        }
    }
}

pub fn handle_terminal_click(
    _win_x: u32,
    _win_y: u32,
    _win_w: u32,
    _win_h: u32,
    _mx: i32,
    _my: i32,
) -> bool {
    false
}

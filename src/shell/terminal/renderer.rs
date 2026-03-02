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

use crate::graphics::framebuffer::{fill_rect, put_pixel, dimensions};
use crate::graphics::font::draw_char;

pub const TERM_W: u32 = 640;
pub const TERM_H: u32 = 480;
pub const TERM_PADDING: u32 = 12;
pub const TERM_TITLE_H: u32 = 28;
pub const LINE_HEIGHT: u32 = 18;
pub const CHAR_WIDTH: u32 = 8;
pub const MAX_COLS: u32 = (TERM_W - TERM_PADDING * 2) / CHAR_WIDTH;
pub const MAX_ROWS: u32 = (TERM_H - TERM_TITLE_H - TERM_PADDING * 2) / LINE_HEIGHT;

// NONOS Brand Terminal Colors
pub const COLOR_BG: u32 = 0xFF080C12;
pub const COLOR_TITLE_BG: u32 = 0xFF111820;
pub const COLOR_BORDER: u32 = 0xFF1E2832;
pub const COLOR_TEXT: u32 = 0xFFF0F6FC;
pub const COLOR_TEXT_DIM: u32 = 0xFF6E7A88;
pub const COLOR_PROMPT: u32 = 0xFF00FF88;
pub const COLOR_CURSOR: u32 = 0xFF00D4FF;
pub const COLOR_SELECTION: u32 = 0x4000D4FF;
pub const COLOR_ERROR: u32 = 0xFFFF4466;
pub const COLOR_WARNING: u32 = 0xFFFFB800;
pub const COLOR_SUCCESS: u32 = 0xFF00FF88;
pub const COLOR_ACCENT: u32 = 0xFF00D4FF;
pub const COLOR_BUTTON_CLOSE: u32 = 0xFFFF4466;
pub const COLOR_BUTTON_MIN: u32 = 0xFFFFB800;
pub const COLOR_BUTTON_MAX: u32 = 0xFF00FF88;

static mut TERM_X: u32 = 0;
static mut TERM_Y: u32 = 0;

pub fn init() {
    let (w, _) = dimensions();
    // SAFETY: TERM_X and TERM_Y are only set during initialization from the main thread.
    unsafe {
        TERM_X = w - TERM_W - 40;
        TERM_Y = 72;
    }
}

pub fn term_x() -> u32 {
    // SAFETY: TERM_X is only accessed after initialization and from the main thread.
    unsafe { TERM_X }
}

pub fn term_y() -> u32 {
    // SAFETY: TERM_Y is only accessed after initialization and from the main thread.
    unsafe { TERM_Y }
}

pub fn content_x() -> u32 {
    term_x() + TERM_PADDING
}

pub fn content_y() -> u32 {
    term_y() + TERM_TITLE_H + TERM_PADDING
}

pub fn content_width() -> u32 {
    TERM_W - TERM_PADDING * 2
}

pub fn content_height() -> u32 {
    TERM_H - TERM_TITLE_H - TERM_PADDING * 2
}

pub fn draw_window() {
    let tx = term_x();
    let ty = term_y();

    fill_rect(tx + 4, ty + 4, TERM_W, TERM_H, 0x40000000);

    fill_rect(tx, ty, TERM_W, TERM_H, COLOR_BG);

    fill_rect(tx, ty, TERM_W, 1, COLOR_BORDER);
    fill_rect(tx, ty + TERM_H - 1, TERM_W, 1, COLOR_BORDER);
    fill_rect(tx, ty, 1, TERM_H, COLOR_BORDER);
    fill_rect(tx + TERM_W - 1, ty, 1, TERM_H, COLOR_BORDER);

    fill_rect(tx + 1, ty + 1, TERM_W - 2, TERM_TITLE_H - 1, COLOR_TITLE_BG);
    fill_rect(tx, ty + TERM_TITLE_H, TERM_W, 1, COLOR_BORDER);

    draw_circle(tx + 18, ty + 14, 6, COLOR_BUTTON_CLOSE);
    draw_circle(tx + 38, ty + 14, 6, COLOR_BUTTON_MIN);
    draw_circle(tx + 58, ty + 14, 6, COLOR_BUTTON_MAX);

    let title = b"N\xd8NOS Terminal";
    for (i, &ch) in title.iter().enumerate() {
        draw_char(tx + 80 + (i as u32) * CHAR_WIDTH, ty + 8, ch, COLOR_TEXT);
    }

    let status_x = tx + TERM_W - 100;
    draw_circle(status_x, ty + 14, 4, COLOR_SUCCESS);
    let status = b"ZeroState";
    for (i, &ch) in status.iter().enumerate() {
        draw_char(status_x + 12 + (i as u32) * CHAR_WIDTH, ty + 8, ch, COLOR_SUCCESS);
    }
}

fn draw_circle(cx: u32, cy: u32, r: u32, color: u32) {
    for dy in 0..=r {
        for dx in 0..=r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(cx + dx, cy + dy, color);
                if dy > 0 {
                    put_pixel(cx + dx, cy - dy, color);
                }
                if dx > 0 {
                    put_pixel(cx - dx, cy + dy, color);
                }
                if dx > 0 && dy > 0 {
                    put_pixel(cx - dx, cy - dy, color);
                }
            }
        }
    }
}

pub fn draw_char_at(col: u32, row: u32, ch: u8, color: u32) {
    let x = content_x() + col * CHAR_WIDTH;
    let y = content_y() + row * LINE_HEIGHT;
    draw_char(x, y, ch, color);
}

pub fn draw_text_at(col: u32, row: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        let c = col + i as u32;
        if c >= MAX_COLS {
            break;
        }
        draw_char_at(c, row, ch, color);
    }
}

pub fn clear_char_at(col: u32, row: u32) {
    let x = content_x() + col * CHAR_WIDTH;
    let y = content_y() + row * LINE_HEIGHT;
    fill_rect(x, y, CHAR_WIDTH, LINE_HEIGHT, COLOR_BG);
}

pub fn clear_row(row: u32) {
    let y = content_y() + row * LINE_HEIGHT;
    fill_rect(content_x(), y, content_width(), LINE_HEIGHT, COLOR_BG);
}

pub fn clear_content() {
    fill_rect(content_x(), content_y(), content_width(), content_height(), COLOR_BG);
}

pub fn draw_cursor(col: u32, row: u32, visible: bool) {
    let x = content_x() + col * CHAR_WIDTH;
    let y = content_y() + row * LINE_HEIGHT;
    let color = if visible { COLOR_CURSOR } else { COLOR_BG };
    fill_rect(x, y, CHAR_WIDTH, LINE_HEIGHT, color);
}

pub fn draw_selection(start_col: u32, end_col: u32, row: u32) {
    let x = content_x() + start_col * CHAR_WIDTH;
    let width = (end_col - start_col) * CHAR_WIDTH;
    let y = content_y() + row * LINE_HEIGHT;
    fill_rect(x, y, width, LINE_HEIGHT, COLOR_SELECTION);
}

pub fn scroll_up_region(start_row: u32, end_row: u32, lines: u32) {
    if lines == 0 || start_row >= end_row {
        return;
    }

    for row in start_row..(end_row - lines) {
        clear_row(row);
    }

    for row in (end_row - lines)..end_row {
        clear_row(row);
    }
}

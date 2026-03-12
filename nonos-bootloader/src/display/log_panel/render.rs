// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/*
 * Log panel rendering - draws only newest entry with line clear.
 */

use crate::display::constants::{
    COLOR_ACCENT, COLOR_ERROR, COLOR_SUCCESS, COLOR_TEXT_DIM, COLOR_WARNING,
};
use crate::display::font::{draw_string, CHAR_HEIGHT};
use crate::display::gop::fill_rect;

use super::buffer::get_entry;
use super::types::{LogLevel, LINE_HEIGHT, LOG_LINE_LEN, LOG_X, LOG_Y_START, MAX_LOG_LINES};

const LINE_WIDTH: u32 = (LOG_LINE_LEN as u32 + 5) * 8;

fn clear_line(y: u32) {
    fill_rect(LOG_X, y, LINE_WIDTH, CHAR_HEIGHT, 0xFF0A0A0A);
}

fn draw_entry(line_num: usize, entry_idx: usize) {
    let y = LOG_Y_START + (line_num as u32) * LINE_HEIGHT;
    clear_line(y);

    if let Some(entry) = get_entry(entry_idx) {
        if entry.len == 0 {
            return;
        }

        let (prefix, color) = match entry.level {
            LogLevel::Info => (b"    " as &[u8], COLOR_TEXT_DIM),
            LogLevel::Ok => (b"[+] " as &[u8], COLOR_SUCCESS),
            LogLevel::Warn => (b"[!] " as &[u8], COLOR_WARNING),
            LogLevel::Error => (b"[X] " as &[u8], COLOR_ERROR),
            LogLevel::Security => (b"[S] " as &[u8], COLOR_ACCENT),
        };

        draw_string(LOG_X, y, prefix, color);
        draw_string(LOG_X + 32, y, &entry.text[..entry.len], color);
    }
}

pub fn redraw_all() {}

pub fn clear_display() {}

fn log_delay() {
    for _ in 0..500_000 {
        core::hint::spin_loop();
    }
}

pub fn render_after_log(count: usize) {
    if count == 0 {
        return;
    }

    let line_num = (count - 1) % MAX_LOG_LINES;
    let entry_idx = line_num;
    draw_entry(line_num, entry_idx);
    log_delay();
}

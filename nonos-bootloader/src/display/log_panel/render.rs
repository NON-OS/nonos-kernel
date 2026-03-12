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
 * Log panel rendering - transparent, no boxes.
 */

use crate::display::constants::{
    COLOR_ACCENT, COLOR_ERROR, COLOR_SUCCESS, COLOR_TEXT_DIM, COLOR_WARNING,
};
use crate::display::font::draw_string;

use super::buffer::{get_count, get_entry};
use super::types::{LogLevel, LINE_HEIGHT, LOG_X, LOG_Y_START, MAX_LOG_LINES};

pub fn redraw_visible(total: usize) {
    if total == 0 {
        return;
    }

    let visible_count = total.min(MAX_LOG_LINES);
    let start_entry = if total > MAX_LOG_LINES { total - MAX_LOG_LINES } else { 0 };

    for line in 0..visible_count {
        let entry_idx = (start_entry + line) % MAX_LOG_LINES;
        let y = LOG_Y_START + (line as u32) * LINE_HEIGHT;

        if let Some(entry) = get_entry(entry_idx) {
            if entry.len == 0 {
                continue;
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
}

pub fn redraw_all() {
    let count = get_count();
    redraw_visible(count);
}

pub fn clear_display() {}

fn log_delay() {
    for _ in 0..800_000 {
        core::hint::spin_loop();
    }
}

pub fn render_after_log(count: usize) {
    redraw_visible(count);
    log_delay();
}

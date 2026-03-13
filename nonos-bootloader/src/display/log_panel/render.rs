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

use crate::display::background::render_region;
use crate::display::constants::{
    COLOR_ACCENT, COLOR_ERROR, COLOR_SUCCESS, COLOR_TEXT_DIM, COLOR_WARNING,
};
use crate::display::font::draw_string;

use super::buffer::get_entry;
use super::types::{LogLevel, LINE_HEIGHT, LOG_LINE_LEN, LOG_X, LOG_Y_START, MAX_LOG_LINES};

const LOG_AREA_WIDTH: u32 = (LOG_LINE_LEN as u32 + 5) * 8;
const LOG_AREA_HEIGHT: u32 = (MAX_LOG_LINES as u32) * LINE_HEIGHT + 4;

fn clear_log_area() {
    render_region(LOG_X - 2, LOG_Y_START - 2, LOG_AREA_WIDTH, LOG_AREA_HEIGHT);
}

fn draw_entry_at(line_num: usize, entry_idx: usize) {
    let y = LOG_Y_START + (line_num as u32) * LINE_HEIGHT;

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

fn redraw_all_visible(total: usize) {
    if total == 0 {
        return;
    }

    let visible_count = total.min(MAX_LOG_LINES);
    let start_entry = if total > MAX_LOG_LINES { total - MAX_LOG_LINES } else { 0 };

    for line in 0..visible_count {
        let entry_idx = (start_entry + line) % MAX_LOG_LINES;
        draw_entry_at(line, entry_idx);
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

    if count > MAX_LOG_LINES {
        clear_log_area();
        redraw_all_visible(count);
    } else {
        let line_num = count - 1;
        let entry_idx = line_num;
        draw_entry_at(line_num, entry_idx);
    }
    log_delay();
}

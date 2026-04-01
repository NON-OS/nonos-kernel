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

use crate::display::constants::{COLOR_ACCENT, COLOR_ERROR, COLOR_SUCCESS, COLOR_WARNING};
use crate::display::font::draw_string;
use crate::display::gop::fill_rect;

use super::buffer::{get_count, get_entry};
use super::types::{get_log_area, LogLevel, LINE_HEIGHT, LOG_LINE_LEN, MAX_LOG_LINES};

const COLOR_INFO: u32 = 0xFF6B7280;
const BG_COLOR: u32 = 0xFF000000;
const LOG_LINE_WIDTH: u32 = (LOG_LINE_LEN as u32 + 4) * 8;

fn clear_line(line_num: usize) {
    let (log_x, log_y) = get_log_area();
    let y = log_y + (line_num as u32) * LINE_HEIGHT;
    fill_rect(log_x, y, LOG_LINE_WIDTH, LINE_HEIGHT, BG_COLOR);
}

fn draw_entry_at(line_num: usize, entry_idx: usize) {
    let (log_x, log_y) = get_log_area();
    let y = log_y + (line_num as u32) * LINE_HEIGHT;

    clear_line(line_num);

    if let Some(entry) = get_entry(entry_idx) {
        if entry.len == 0 {
            return;
        }

        let (prefix, color) = match entry.level {
            LogLevel::Info => (b"    " as &[u8], COLOR_INFO),
            LogLevel::Ok => (b"[+] " as &[u8], COLOR_SUCCESS),
            LogLevel::Warn => (b"[!] " as &[u8], COLOR_WARNING),
            LogLevel::Error => (b"[X] " as &[u8], COLOR_ERROR),
            LogLevel::Security => (b"[S] " as &[u8], COLOR_ACCENT),
        };

        draw_string(log_x, y, prefix, color);
        draw_string(log_x + 32, y, &entry.text[..entry.len], color);
    }
}

fn redraw_all_visible(total: usize) {
    if total == 0 {
        return;
    }

    let visible_count = total.min(MAX_LOG_LINES);
    let start_entry = if total > MAX_LOG_LINES {
        total - MAX_LOG_LINES
    } else {
        0
    };

    for line in 0..visible_count {
        let entry_idx = (start_entry + line) % MAX_LOG_LINES;
        draw_entry_at(line, entry_idx);
    }
}

pub fn redraw_all() {
    let count = get_count();
    if count > 0 {
        redraw_all_visible(count);
    }
}

pub fn clear_display() {
    let (log_x, log_y) = get_log_area();
    let height = (MAX_LOG_LINES as u32) * LINE_HEIGHT;
    fill_rect(log_x, log_y, LOG_LINE_WIDTH, height, BG_COLOR);
}

fn log_delay() {
    for _ in 0..300_000 {
        core::hint::spin_loop();
    }
}

pub fn render_after_log(count: usize) {
    if count == 0 {
        return;
    }

    if count > MAX_LOG_LINES {
        redraw_all_visible(count);
    } else {
        let line_num = count - 1;
        let entry_idx = line_num;
        draw_entry_at(line_num, entry_idx);
    }
    log_delay();
}

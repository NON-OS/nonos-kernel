// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::history::{self, HistoryEntry};
use crate::graphics::design_system::colors;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::rounded_rect_blend;

const ENTRY_HEIGHT: u32 = 40;
const PADDING: u32 = 12;

pub(crate) fn draw_history_panel(x: u32, y: u32, w: u32, h: u32) {
    rounded_rect_blend(x, y, w, h, 12, colors::GLASS_BG);
    draw_text(x + PADDING, y + PADDING, b"History", colors::TEXT_PRIMARY);
    let count = history::get_count();
    if count == 0 {
        draw_text(x + PADDING, y + 48, b"No calculations yet", colors::TEXT_SECONDARY);
        return;
    }
    let entry_y_start = y + 48;
    let max_visible = ((h - 60) / ENTRY_HEIGHT) as usize;
    let start_idx = if count > max_visible { count - max_visible } else { 0 };
    for (i, idx) in (start_idx..count).enumerate() {
        if let Some(entry) = history::get_entry(idx) {
            let ey = entry_y_start + i as u32 * ENTRY_HEIGHT;
            draw_history_entry(x + PADDING, ey, w - PADDING * 2, &entry);
        }
    }
}

fn draw_history_entry(x: u32, y: u32, w: u32, entry: &HistoryEntry) {
    rounded_rect_blend(x, y, w, ENTRY_HEIGHT - 4, 8, colors::GLASS_BG_LIGHT);
    let mut buf = [0u8; 32];
    let len = format_entry(&mut buf, entry);
    draw_text(x + 8, y + 8, &buf[..len], colors::TEXT_SECONDARY);
    let result_str = format_number(entry.result);
    let result_x = x + w - 8 - result_str.len() as u32 * 8;
    draw_text(result_x, y + 20, &result_str, colors::TEXT_PRIMARY);
}

fn format_entry(buf: &mut [u8], entry: &HistoryEntry) -> usize {
    let mut pos = 0;
    pos += write_i64(&mut buf[pos..], entry.operand1 / 100);
    buf[pos] = b' ';
    pos += 1;
    buf[pos] = history::operator_char(entry.operator);
    pos += 1;
    buf[pos] = b' ';
    pos += 1;
    pos += write_i64(&mut buf[pos..], entry.operand2 / 100);
    buf[pos] = b' ';
    pos += 1;
    buf[pos] = b'=';
    pos += 1;
    pos
}

fn format_number(val: i64) -> [u8; 16] {
    let mut buf = [b' '; 16];
    let mut pos = 15;
    let mut v = (val / 100).abs();
    if v == 0 {
        buf[pos] = b'0';
        pos -= 1;
    } else {
        while v > 0 && pos > 0 {
            buf[pos] = b'0' + (v % 10) as u8;
            v /= 10;
            pos -= 1;
        }
    }
    if val < 0 && pos > 0 {
        buf[pos] = b'-';
    }
    buf
}

fn write_i64(buf: &mut [u8], val: i64) -> usize {
    let mut v = val.abs();
    let neg = val < 0;
    let mut digits = [0u8; 20];
    let mut count = 0;
    if v == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while v > 0 {
            digits[count] = b'0' + (v % 10) as u8;
            v /= 10;
            count += 1;
        }
    }
    let mut pos = 0;
    if neg {
        buf[pos] = b'-';
        pos += 1;
    }
    for i in (0..count).rev() {
        buf[pos] = digits[i];
        pos += 1;
    }
    pos
}

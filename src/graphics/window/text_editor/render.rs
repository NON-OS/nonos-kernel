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
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use super::state::*;
use super::render_ui::{draw_file_picker, draw_toolbar, draw_line_numbers, draw_line_number, draw_status_bar};

fn syntax_color(ch: u8) -> u32 {
    match ch {
        b'/' | b'*' => 0xFF7D8590,
        b'"' | b'\'' => 0xFF3FB950,
        b'0'..=b'9' => 0xFFD29922,
        b'{' | b'}' | b'(' | b')' | b'[' | b']' => COLOR_ACCENT,
        b';' | b':' => 0xFFD29922,
        b'#' => 0xFF7D8590,
        _ => COLOR_TEXT_WHITE,
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    if picker_is_active() {
        draw_file_picker(x, y, w, h);
        return;
    }

    draw_toolbar(x, y, w);
    draw_line_numbers(x, y + TOOLBAR_HEIGHT, h - TOOLBAR_HEIGHT - STATUS_BAR_HEIGHT);
    draw_text_area(x, y, w, h);
    draw_status_bar(x, y, w, h);
}

fn draw_text_area(x: u32, y: u32, w: u32, h: u32) {
    let text_area_y = y + TOOLBAR_HEIGHT;
    let text_area_h = h - TOOLBAR_HEIGHT - STATUS_BAR_HEIGHT;

    fill_rect(x + LINE_NUM_WIDTH, text_area_y, w - LINE_NUM_WIDTH, text_area_h, 0xFF0D1117);

    let editor_len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor_pos = EDITOR_CURSOR.load(Ordering::Relaxed);
    let scroll_y = EDITOR_SCROLL_Y.load(Ordering::Relaxed);
    let has_selection = EDITOR_HAS_SELECTION.load(Ordering::Relaxed);
    let sel_start = EDITOR_SELECTION_START.load(Ordering::Relaxed);
    let sel_end = EDITOR_SELECTION_END.load(Ordering::Relaxed);

    let text_x = x + LINE_NUM_WIDTH + 10;
    let text_y = text_area_y + 10;
    let max_lines = ((text_area_h - 20) / LINE_HEIGHT) as usize;
    let chars_per_line = ((w - LINE_NUM_WIDTH - 20) / 8) as usize;

    let (sel_min, sel_max) = if sel_start < sel_end {
        (sel_start, sel_end)
    } else {
        (sel_end, sel_start)
    };

    let mut line = 0usize;
    let mut col = 0usize;
    let mut char_idx = 0usize;

    // SAFETY: Single-threaded access to editor buffer during render
    unsafe {
        while char_idx < editor_len {
            let ch = EDITOR_BUFFER[char_idx];

            if line >= scroll_y && line < scroll_y + max_lines {
                let display_line = (line - scroll_y) as u32;

                if col == 0 {
                    draw_line_number(x, text_y + display_line * LINE_HEIGHT, line + 1);
                }

                if has_selection && char_idx >= sel_min && char_idx < sel_max {
                    fill_rect(
                        text_x + (col as u32) * 8,
                        text_y + display_line * LINE_HEIGHT,
                        8,
                        LINE_HEIGHT,
                        0xFF264F78,
                    );
                }

                if char_idx == cursor_pos {
                    fill_rect(
                        text_x + (col as u32) * 8,
                        text_y + display_line * LINE_HEIGHT,
                        2,
                        16,
                        COLOR_ACCENT,
                    );
                }

                if ch != b'\n' {
                    let color = syntax_color(ch);
                    draw_char(text_x + (col as u32) * 8, text_y + display_line * LINE_HEIGHT, ch, color);
                }
            }

            if ch == b'\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
                if col >= chars_per_line {
                    col = 0;
                    line += 1;
                }
            }

            char_idx += 1;
        }

        if cursor_pos >= editor_len && line >= scroll_y && line < scroll_y + max_lines {
            let display_line = (line - scroll_y) as u32;
            if col == 0 {
                draw_line_number(x, text_y + display_line * LINE_HEIGHT, line + 1);
            }
            fill_rect(
                text_x + (col as u32) * 8,
                text_y + display_line * LINE_HEIGHT,
                2,
                16,
                COLOR_ACCENT,
            );
        }
    }
}

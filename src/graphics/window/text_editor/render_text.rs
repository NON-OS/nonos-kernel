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

use super::render_text_draw::{draw_cursor_at_end, draw_line_tokens};
use super::render_ui::draw_line_number;
use super::state::*;
use super::syntax::tokenize_line;
use crate::graphics::framebuffer::fill_rect;
use core::sync::atomic::Ordering;

pub(super) fn draw_text_area(x: u32, y: u32, w: u32, h: u32) {
    let text_area_y = y + TOOLBAR_HEIGHT;
    let text_area_h = h - TOOLBAR_HEIGHT - STATUS_BAR_HEIGHT;
    fill_rect(x + LINE_NUM_WIDTH, text_area_y, w - LINE_NUM_WIDTH, text_area_h, 0xFF0D1117);

    let editor_len = EDITOR_LEN.load(Ordering::Relaxed);
    let cursor_pos = EDITOR_CURSOR.load(Ordering::Relaxed);
    let scroll_y = EDITOR_SCROLL_Y.load(Ordering::Relaxed);
    let text_x = x + LINE_NUM_WIDTH + 10;
    let text_y = text_area_y + 10;
    let max_lines = ((text_area_h - 20) / LINE_HEIGHT) as usize;
    let chars_per_line = ((w - LINE_NUM_WIDTH - 20) / 8) as usize;

    let lines = extract_visible_lines(scroll_y, max_lines, editor_len);
    for (disp_idx, (line_num, line_start, line_data)) in lines.iter().enumerate() {
        let dy = text_y + (disp_idx as u32) * LINE_HEIGHT;
        draw_line_number(x, dy, *line_num);
        draw_line_tokens(
            text_x,
            dy,
            &tokenize_line(line_data),
            *line_start,
            cursor_pos,
            chars_per_line,
        );
    }
    draw_cursor_at_end(text_x, text_y, cursor_pos, editor_len, scroll_y, max_lines, x);
}

fn extract_visible_lines(
    scroll_y: usize,
    max: usize,
    len: usize,
) -> alloc::vec::Vec<(usize, usize, alloc::vec::Vec<u8>)> {
    let mut result = alloc::vec::Vec::new();
    let mut line_num = 1usize;
    let mut line_start = 0usize;
    let mut cur = alloc::vec::Vec::new();
    unsafe {
        for i in 0..len {
            let ch = EDITOR_BUFFER[i];
            if ch == b'\n' {
                if line_num > scroll_y && result.len() < max {
                    result.push((line_num, line_start, cur.clone()));
                }
                line_num += 1;
                line_start = i + 1;
                cur.clear();
            } else {
                cur.push(ch);
            }
        }
        if line_num > scroll_y && result.len() < max {
            result.push((line_num, line_start, cur));
        }
    }
    result
}

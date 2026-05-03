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

use super::find_search::{is_current_match_position, is_match_position};
use super::render_ui::draw_line_number;
use super::state::*;
use super::syntax::{token_color, TokenType};
use crate::graphics::font::draw_char;
use crate::display::framebuffer::{COLOR_ACCENT};
use crate::graphics::framebuffer::{fill_rect};
use core::sync::atomic::Ordering;

pub(super) fn draw_line_tokens(
    px: u32,
    py: u32,
    tokens: &[(u8, TokenType)],
    start: usize,
    cursor: usize,
    max: usize,
) {
    let has_sel = EDITOR_HAS_SELECTION.load(Ordering::Relaxed);
    let (s0, s1) = (
        EDITOR_SELECTION_START.load(Ordering::Relaxed),
        EDITOR_SELECTION_END.load(Ordering::Relaxed),
    );
    let (sel_min, sel_max) = if s0 < s1 { (s0, s1) } else { (s1, s0) };

    for (col, (ch, tt)) in tokens.iter().enumerate() {
        if col >= max {
            break;
        }
        let idx = start + col;
        let x = px + (col as u32) * 8;
        if has_sel && idx >= sel_min && idx < sel_max {
            fill_rect(x, py, 8, LINE_HEIGHT, 0xFF264F78);
        } else if is_current_match_position(idx) {
            fill_rect(x, py, 8, LINE_HEIGHT, 0xFFD29922);
        } else if is_match_position(idx) {
            fill_rect(x, py, 8, LINE_HEIGHT, 0xFF3D4A3A);
        }
        if idx == cursor {
            fill_rect(x, py, 2, 16, COLOR_ACCENT);
        }
        draw_char(x, py, *ch, token_color(*tt));
    }
    let end_idx = start + tokens.len();
    if cursor == end_idx && tokens.len() < max {
        fill_rect(px + (tokens.len() as u32) * 8, py, 2, 16, COLOR_ACCENT);
    }
}

pub(super) fn draw_cursor_at_end(
    px: u32,
    py: u32,
    cursor: usize,
    len: usize,
    scroll: usize,
    max: usize,
    x: u32,
) {
    if cursor >= len {
        let (mut line, mut col) = (0usize, 0usize);
        unsafe {
            for i in 0..len {
                if EDITOR_BUFFER[i] == b'\n' {
                    line += 1;
                    col = 0;
                } else {
                    col += 1;
                }
            }
        }
        if line >= scroll && line < scroll + max {
            let dy = (line - scroll) as u32;
            if col == 0 {
                draw_line_number(x, py + dy * LINE_HEIGHT, line + 1);
            }
            fill_rect(px + (col as u32) * 8, py + dy * LINE_HEIGHT, 2, 16, COLOR_ACCENT);
        }
    }
}

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

use core::ptr::addr_of_mut;

use crate::shell::terminal::renderer::{MAX_COLS, MAX_ROWS, COLOR_TEXT};

use super::cell::ScreenCell;

pub const SCROLLBACK_LINES: usize = 512;
pub const MAX_LINE_LEN: usize = 256;

pub struct ScreenBuffer {
    lines: [[ScreenCell; MAX_LINE_LEN]; SCROLLBACK_LINES],
    line_lengths: [usize; SCROLLBACK_LINES],
    total_lines: usize,
    view_offset: usize,
    cursor_row: u32,
    cursor_col: u32,
}

impl ScreenBuffer {
    pub const fn new() -> Self {
        const DEFAULT_CELL: ScreenCell = ScreenCell {
            ch: b' ',
            color: COLOR_TEXT,
        };
        const DEFAULT_LINE: [ScreenCell; MAX_LINE_LEN] = [DEFAULT_CELL; MAX_LINE_LEN];

        Self {
            lines: [DEFAULT_LINE; SCROLLBACK_LINES],
            line_lengths: [0; SCROLLBACK_LINES],
            total_lines: 0,
            view_offset: 0,
            cursor_row: 0,
            cursor_col: 0,
        }
    }

    pub fn clear(&mut self) {
        for i in 0..SCROLLBACK_LINES {
            self.line_lengths[i] = 0;
            for j in 0..MAX_LINE_LEN {
                self.lines[i][j] = ScreenCell::default();
            }
        }
        self.total_lines = 0;
        self.view_offset = 0;
        self.cursor_row = 0;
        self.cursor_col = 0;
    }

    pub fn cursor_row(&self) -> u32 {
        self.cursor_row
    }

    pub fn cursor_col(&self) -> u32 {
        self.cursor_col
    }

    pub fn set_cursor(&mut self, col: u32, row: u32) {
        self.cursor_col = col.min(MAX_COLS - 1);
        self.cursor_row = row.min(MAX_ROWS - 1);
    }

    pub fn move_cursor_right(&mut self) {
        if self.cursor_col < MAX_COLS - 1 {
            self.cursor_col += 1;
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        }
    }

    pub fn move_cursor_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
        }
    }

    pub fn move_cursor_down(&mut self) {
        if self.cursor_row < MAX_ROWS - 1 {
            self.cursor_row += 1;
        }
    }

    pub fn put_char(&mut self, ch: u8, color: u32) {
        let line_idx = (self.view_offset + self.cursor_row as usize) % SCROLLBACK_LINES;
        let col = self.cursor_col as usize;

        if col < MAX_LINE_LEN {
            self.lines[line_idx][col] = ScreenCell { ch, color };
            if col >= self.line_lengths[line_idx] {
                self.line_lengths[line_idx] = col + 1;
            }
        }

        if self.cursor_col < MAX_COLS - 1 {
            self.cursor_col += 1;
        }
    }

    pub fn put_line(&mut self, text: &[u8], color: u32) {
        let line_idx = (self.view_offset + self.cursor_row as usize) % SCROLLBACK_LINES;
        let len = text.len().min(MAX_LINE_LEN);

        for (i, &ch) in text[..len].iter().enumerate() {
            self.lines[line_idx][i] = ScreenCell { ch, color };
        }
        self.line_lengths[line_idx] = len;

        self.newline();
    }

    pub fn newline(&mut self) {
        self.cursor_col = 0;
        if self.cursor_row < MAX_ROWS - 1 {
            self.cursor_row += 1;
        } else {
            self.scroll_up();
        }

        if self.total_lines < SCROLLBACK_LINES {
            self.total_lines += 1;
        }
    }

    pub fn scroll_up(&mut self) {
        self.view_offset = (self.view_offset + 1) % SCROLLBACK_LINES;

        let new_line_idx = (self.view_offset + MAX_ROWS as usize - 1) % SCROLLBACK_LINES;
        self.line_lengths[new_line_idx] = 0;
        for i in 0..MAX_LINE_LEN {
            self.lines[new_line_idx][i] = ScreenCell::default();
        }
    }

    pub fn scroll_view_up(&mut self, lines: usize) -> bool {
        let max_scroll = self.total_lines.saturating_sub(MAX_ROWS as usize);
        if self.view_offset > 0 && max_scroll > 0 {
            self.view_offset = self.view_offset.saturating_sub(lines);
            true
        } else {
            false
        }
    }

    pub fn scroll_view_down(&mut self, lines: usize) -> bool {
        let max_offset = self.total_lines.saturating_sub(MAX_ROWS as usize);
        if self.view_offset < max_offset {
            self.view_offset = (self.view_offset + lines).min(max_offset);
            true
        } else {
            false
        }
    }

    pub fn get_line(&self, row: u32) -> (&[ScreenCell], usize) {
        let line_idx = (self.view_offset + row as usize) % SCROLLBACK_LINES;
        let len = self.line_lengths[line_idx];
        (&self.lines[line_idx][..len.min(MAX_LINE_LEN)], len)
    }

    pub fn clear_line(&mut self, row: u32) {
        let line_idx = (self.view_offset + row as usize) % SCROLLBACK_LINES;
        self.line_lengths[line_idx] = 0;
        for i in 0..MAX_LINE_LEN {
            self.lines[line_idx][i] = ScreenCell::default();
        }
    }

    pub fn clear_from_cursor(&mut self) {
        let line_idx = (self.view_offset + self.cursor_row as usize) % SCROLLBACK_LINES;
        let col = self.cursor_col as usize;

        for i in col..MAX_LINE_LEN {
            self.lines[line_idx][i] = ScreenCell::default();
        }
        if col < self.line_lengths[line_idx] {
            self.line_lengths[line_idx] = col;
        }
    }

    pub fn insert_char(&mut self, ch: u8, color: u32) {
        let line_idx = (self.view_offset + self.cursor_row as usize) % SCROLLBACK_LINES;
        let col = self.cursor_col as usize;
        let len = self.line_lengths[line_idx];

        if len < MAX_LINE_LEN - 1 {
            for i in (col..len).rev() {
                self.lines[line_idx][i + 1] = self.lines[line_idx][i];
            }
            self.lines[line_idx][col] = ScreenCell { ch, color };
            self.line_lengths[line_idx] = len + 1;
            self.cursor_col += 1;
        }
    }

    pub fn delete_char(&mut self) {
        let line_idx = (self.view_offset + self.cursor_row as usize) % SCROLLBACK_LINES;
        let col = self.cursor_col as usize;
        let len = self.line_lengths[line_idx];

        if col < len {
            for i in col..(len - 1) {
                self.lines[line_idx][i] = self.lines[line_idx][i + 1];
            }
            self.lines[line_idx][len - 1] = ScreenCell::default();
            self.line_lengths[line_idx] = len - 1;
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
            self.delete_char();
        }
    }
}

static mut SCREEN_BUFFER: ScreenBuffer = ScreenBuffer::new();

pub fn get_buffer() -> &'static mut ScreenBuffer {
    // SAFETY: Screen buffer is only accessed from the main thread during terminal operations.
    // No concurrent access occurs as the shell is single-threaded.
    unsafe { &mut *addr_of_mut!(SCREEN_BUFFER) }
}

pub fn init() {
    get_buffer().clear();
}

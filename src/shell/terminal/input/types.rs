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

use crate::shell::terminal::history;
use crate::shell::terminal::renderer::{
    clear_row, draw_char_at, draw_cursor, COLOR_PROMPT, COLOR_TEXT, MAX_COLS,
};

pub const MAX_INPUT_LEN: usize = 240;
pub const PROMPT_LEN: usize = 7;

pub struct LineEditor {
    pub(crate) buffer: [u8; MAX_INPUT_LEN],
    pub(crate) length: usize,
    pub(crate) cursor_pos: usize,
    pub(crate) prompt_col: u32,
    pub(crate) row: u32,
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; MAX_INPUT_LEN],
            length: 0,
            cursor_pos: 0,
            prompt_col: PROMPT_LEN as u32,
            row: 0,
        }
    }

    pub fn reset(&mut self, row: u32) {
        self.buffer = [0u8; MAX_INPUT_LEN];
        self.length = 0;
        self.cursor_pos = 0;
        self.row = row;
    }

    pub fn set_row(&mut self, row: u32) {
        self.row = row;
    }

    pub fn row(&self) -> u32 {
        self.row
    }

    pub fn get_content(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn cursor_pos(&self) -> usize {
        self.cursor_pos
    }

    pub fn cursor_col(&self) -> u32 {
        self.prompt_col + self.cursor_pos as u32
    }

    pub fn set_content(&mut self, content: &[u8]) {
        let len = content.len().min(MAX_INPUT_LEN - 1);
        self.buffer[..len].copy_from_slice(&content[..len]);
        for i in len..MAX_INPUT_LEN {
            self.buffer[i] = 0;
        }
        self.length = len;
        self.cursor_pos = len;
        self.redraw();
    }

    pub fn history_prev(&mut self) {
        if let Some((cmd, len)) = history::prev_command(&self.buffer[..self.length]) {
            self.set_content(&cmd[..len]);
        }
    }

    pub fn history_next(&mut self) {
        if let Some((cmd, len)) = history::next_command() {
            self.set_content(&cmd[..len]);
        }
    }

    pub fn redraw(&self) {
        clear_row(self.row);

        let prompt = b"n\xd8nos>";
        for (i, &ch) in prompt.iter().enumerate() {
            draw_char_at(i as u32, self.row, ch, COLOR_PROMPT);
        }

        let max_display = (MAX_COLS as usize - PROMPT_LEN).min(self.length);
        for i in 0..max_display {
            draw_char_at(self.prompt_col + i as u32, self.row, self.buffer[i], COLOR_TEXT);
        }

        self.update_cursor();
    }

    pub(crate) fn update_cursor(&self) {
        let col = self.cursor_col();
        draw_cursor(col, self.row, true);
    }

    pub fn show_cursor(&self, visible: bool) {
        let col = self.cursor_col();
        draw_cursor(col, self.row, visible);
    }

    pub fn draw_prompt(&self) {
        let prompt = b"n\xd8nos>";
        for (i, &ch) in prompt.iter().enumerate() {
            draw_char_at(i as u32, self.row, ch, COLOR_PROMPT);
        }
        self.update_cursor();
    }
}

static mut LINE_EDITOR: LineEditor = LineEditor::new();

pub fn get_editor() -> &'static mut LineEditor {
    // SAFETY: Line editor is only accessed from the main thread during terminal
    // operations. No concurrent access occurs as the shell is single-threaded.
    unsafe { &mut *addr_of_mut!(LINE_EDITOR) }
}

pub fn init() {
    get_editor().reset(0);
}

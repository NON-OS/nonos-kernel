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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::editor::buffer::Buffer;
use crate::shell::editor::mode::ModeState;

use super::config::{EditorConfig, VisualSelection, Register};

const MAX_UNDO_HISTORY: usize = 100;

#[derive(Clone)]
pub(super) struct UndoState {
    pub buffer_content: String,
    pub cursor_row: usize,
    pub cursor_col: usize,
}

pub struct Editor {
    pub(super) buffer: Buffer,
    pub(super) mode_state: ModeState,
    pub(super) config: EditorConfig,
    pub(super) cursor_row: usize,
    pub(super) cursor_col: usize,
    pub(super) desired_col: usize,
    pub(super) viewport_row: usize,
    pub(super) viewport_height: usize,
    pub(super) visual_selection: Option<VisualSelection>,
    pub(super) registers: [Register; 26],
    pub(super) default_register: Register,
    pub(super) undo_stack: Vec<UndoState>,
    pub(super) redo_stack: Vec<UndoState>,
    pub(super) message: Option<String>,
    pub(super) error: bool,
}

impl Editor {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
            mode_state: ModeState::new(),
            config: EditorConfig::default(),
            cursor_row: 0,
            cursor_col: 0,
            desired_col: 0,
            viewport_row: 0,
            viewport_height: 24,
            visual_selection: None,
            registers: core::array::from_fn(|_| Register::new()),
            default_register: Register::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            message: None,
            error: false,
        }
    }

    pub fn with_content(content: &str) -> Self {
        let mut editor = Self::new();
        editor.buffer = Buffer::from_string(content);
        editor
    }

    pub fn with_file(filename: &str, content: &str) -> Self {
        let mut editor = Self::new();
        editor.buffer = Buffer::from_file(filename, content);
        editor
    }

    pub fn buffer(&self) -> &Buffer {
        &self.buffer
    }

    pub fn buffer_mut(&mut self) -> &mut Buffer {
        &mut self.buffer
    }

    pub fn mode_state(&self) -> &ModeState {
        &self.mode_state
    }

    pub fn mode_state_mut(&mut self) -> &mut ModeState {
        &mut self.mode_state
    }

    pub fn config(&self) -> &EditorConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut EditorConfig {
        &mut self.config
    }

    pub fn cursor_row(&self) -> usize {
        self.cursor_row
    }

    pub fn cursor_col(&self) -> usize {
        self.cursor_col
    }

    pub fn viewport_row(&self) -> usize {
        self.viewport_row
    }

    pub fn set_viewport_height(&mut self, height: usize) {
        self.viewport_height = height;
    }

    pub fn set_cursor(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(self.buffer.line_count().saturating_sub(1));
        self.cursor_col = col;
        self.desired_col = col;
        self.ensure_cursor_visible();
    }

    pub fn load_file(&mut self, filename: &str, content: &str) {
        self.buffer = Buffer::from_file(filename, content);
        self.cursor_row = 0;
        self.cursor_col = 0;
        self.viewport_row = 0;
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    pub fn new_file(&mut self, filename: &str) {
        self.buffer = Buffer::new();
        self.buffer.set_filename(filename);
        self.cursor_row = 0;
        self.cursor_col = 0;
        self.viewport_row = 0;
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    pub(super) fn save_undo(&mut self) {
        let state = UndoState {
            buffer_content: self.buffer.to_string(),
            cursor_row: self.cursor_row,
            cursor_col: self.cursor_col,
        };

        self.undo_stack.push(state);
        if self.undo_stack.len() > MAX_UNDO_HISTORY {
            self.undo_stack.remove(0);
        }
        self.redo_stack.clear();
    }

    pub fn undo(&mut self) {
        if let Some(state) = self.undo_stack.pop() {
            let current = UndoState {
                buffer_content: self.buffer.to_string(),
                cursor_row: self.cursor_row,
                cursor_col: self.cursor_col,
            };
            self.redo_stack.push(current);

            let filename = self.buffer.filename().map(String::from);
            self.buffer = Buffer::from_string(&state.buffer_content);
            if let Some(ref name) = filename {
                self.buffer.set_filename(name);
            }
            self.cursor_row = state.cursor_row;
            self.cursor_col = state.cursor_col;
        }
    }

    pub fn redo(&mut self) {
        if let Some(state) = self.redo_stack.pop() {
            let current = UndoState {
                buffer_content: self.buffer.to_string(),
                cursor_row: self.cursor_row,
                cursor_col: self.cursor_col,
            };
            self.undo_stack.push(current);

            self.buffer = Buffer::from_string(&state.buffer_content);
            self.cursor_row = state.cursor_row;
            self.cursor_col = state.cursor_col;
        }
    }

    pub(super) fn ensure_cursor_visible(&mut self) {
        let scroll_offset = self.config.scroll_offset;

        if self.cursor_row < self.viewport_row + scroll_offset {
            self.viewport_row = self.cursor_row.saturating_sub(scroll_offset);
        }

        let bottom = self.viewport_row + self.viewport_height - 1 - scroll_offset;
        if self.cursor_row > bottom {
            self.viewport_row = self.cursor_row + scroll_offset + 1 - self.viewport_height;
        }
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn set_message(&mut self, msg: &str) {
        self.message = Some(String::from(msg));
        self.error = false;
    }

    pub fn set_error(&mut self, msg: &str) {
        self.message = Some(String::from(msg));
        self.error = true;
    }

    pub fn clear_message(&mut self) {
        self.message = None;
        self.error = false;
    }

    pub fn is_error(&self) -> bool {
        self.error
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

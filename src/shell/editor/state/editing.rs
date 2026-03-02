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

use crate::shell::editor::buffer::Line;

use super::editor::Editor;

impl Editor {
    pub fn insert_char(&mut self, c: char) {
        self.save_undo();
        self.buffer.insert_char(self.cursor_row, self.cursor_col, c);
        self.cursor_col += 1;
        self.desired_col = self.cursor_col;
    }

    pub fn insert_newline(&mut self) {
        self.save_undo();

        let indent = if self.config.auto_indent {
            self.buffer
                .line(self.cursor_row)
                .map(|l| l.indent_level(self.config.tab_width))
                .unwrap_or(0)
        } else {
            0
        };

        self.buffer.insert_newline(self.cursor_row, self.cursor_col);
        self.cursor_row += 1;
        self.cursor_col = 0;

        if indent > 0 {
            let spaces: String = (0..indent).map(|_| ' ').collect();
            for c in spaces.chars() {
                self.buffer.insert_char(self.cursor_row, self.cursor_col, c);
                self.cursor_col += 1;
            }
        }

        self.desired_col = self.cursor_col;
        self.ensure_cursor_visible();
    }

    pub fn backspace(&mut self) {
        self.save_undo();
        let (new_row, new_col) = self.buffer.backspace(self.cursor_row, self.cursor_col);
        self.cursor_row = new_row;
        self.cursor_col = new_col;
        self.desired_col = new_col;
        self.ensure_cursor_visible();
    }

    pub fn delete_char_at_cursor(&mut self) {
        self.save_undo();
        self.buffer.delete_char(self.cursor_row, self.cursor_col);
        let line_len = self.buffer.line_len(self.cursor_row);
        if self.cursor_col >= line_len && line_len > 0 {
            self.cursor_col = line_len - 1;
        }
    }

    pub fn delete_char_before_cursor(&mut self) {
        if self.cursor_col > 0 {
            self.save_undo();
            self.cursor_col -= 1;
            self.buffer.delete_char(self.cursor_row, self.cursor_col);
            self.desired_col = self.cursor_col;
        }
    }

    pub fn delete_line(&mut self) {
        self.save_undo();
        if let Some(line) = self.buffer.delete_line(self.cursor_row) {
            self.default_register.content = line.content;
            self.default_register.linewise = true;
        }

        if self.cursor_row >= self.buffer.line_count() {
            self.cursor_row = self.buffer.line_count().saturating_sub(1);
        }
        self.cursor_col = 0;
    }

    pub fn insert_line_below(&mut self, row: usize) {
        self.save_undo();
        self.buffer.insert_line(row + 1, Line::new());
    }

    pub fn insert_line_above(&mut self, row: usize) {
        self.save_undo();
        self.buffer.insert_line(row, Line::new());
    }

    pub fn insert_line_at(&mut self, row: usize) {
        self.save_undo();
        self.buffer.insert_line(row, Line::new());
    }

    pub fn replace_char(&mut self, c: char) {
        self.save_undo();
        self.buffer.delete_char(self.cursor_row, self.cursor_col);
        self.buffer.insert_char(self.cursor_row, self.cursor_col, c);
    }

    pub fn yank_line(&mut self) {
        if let Some(line) = self.buffer.line(self.cursor_row) {
            self.default_register.content = line.content.clone();
            self.default_register.linewise = true;
        }
    }

    pub fn paste_after(&mut self) {
        self.save_undo();
        if self.default_register.linewise {
            let new_line = Line::from_str(&self.default_register.content);
            self.buffer.insert_line(self.cursor_row + 1, new_line);
            self.cursor_row += 1;
            self.cursor_col = 0;
        } else {
            for c in self.default_register.content.chars() {
                self.cursor_col += 1;
                self.buffer.insert_char(self.cursor_row, self.cursor_col, c);
            }
        }
    }

    pub fn paste_before(&mut self) {
        self.save_undo();
        if self.default_register.linewise {
            let new_line = Line::from_str(&self.default_register.content);
            self.buffer.insert_line(self.cursor_row, new_line);
            self.cursor_col = 0;
        } else {
            for c in self.default_register.content.chars() {
                self.buffer.insert_char(self.cursor_row, self.cursor_col, c);
                self.cursor_col += 1;
            }
        }
    }
}

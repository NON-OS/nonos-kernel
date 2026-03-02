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

use crate::shell::editor::mode::Mode;

use super::config::{VisualSelection, normalize_selection};
use super::editor::Editor;

impl Editor {
    pub fn start_visual(&mut self, line_wise: bool) {
        self.visual_selection = Some(VisualSelection {
            start_row: self.cursor_row,
            start_col: self.cursor_col,
            end_row: self.cursor_row,
            end_col: self.cursor_col,
            line_wise,
        });
        self.mode_state.set_mode(if line_wise {
            Mode::VisualLine
        } else {
            Mode::Visual
        });
    }

    pub fn extend_visual(&mut self, row: usize, col: usize) {
        if let Some(ref mut sel) = self.visual_selection {
            sel.end_row = row;
            sel.end_col = col;
        }
    }

    pub fn end_visual(&mut self) {
        self.visual_selection = None;
    }

    pub fn visual_selection(&self) -> Option<&VisualSelection> {
        self.visual_selection.as_ref()
    }

    pub fn delete_selection(&mut self) {
        if let Some(sel) = self.visual_selection.take() {
            self.save_undo();
            let (start_row, start_col, end_row, end_col) = normalize_selection(&sel);

            if sel.line_wise {
                for _ in start_row..=end_row {
                    self.buffer.delete_line(start_row);
                }
                self.cursor_row = start_row.min(self.buffer.line_count().saturating_sub(1));
                self.cursor_col = 0;
            } else {
                self.buffer.delete_range(start_row, start_col, end_row, end_col + 1);
                self.cursor_row = start_row;
                self.cursor_col = start_col;
            }
        }
    }

    pub fn yank_selection(&mut self) {
        if let Some(ref sel) = self.visual_selection {
            let (start_row, start_col, end_row, end_col) = normalize_selection(sel);

            if sel.line_wise {
                let mut content = String::new();
                for row in start_row..=end_row {
                    if let Some(line) = self.buffer.line(row) {
                        content.push_str(&line.content);
                        content.push('\n');
                    }
                }
                self.default_register.content = content;
                self.default_register.linewise = true;
            } else {
                self.default_register.content =
                    self.buffer.get_range(start_row, start_col, end_row, end_col + 1);
                self.default_register.linewise = false;
            }
        }
    }

    pub fn delete_range(&mut self, start_row: usize, start_col: usize, end_row: usize, end_col: usize, linewise: bool) {
        self.save_undo();
        if linewise {
            let (sr, er) = if start_row <= end_row {
                (start_row, end_row)
            } else {
                (end_row, start_row)
            };
            for _ in sr..=er {
                self.buffer.delete_line(sr);
            }
            self.cursor_row = sr.min(self.buffer.line_count().saturating_sub(1));
            self.cursor_col = 0;
        } else {
            let (sr, sc, er, ec) = if start_row < end_row || (start_row == end_row && start_col <= end_col) {
                (start_row, start_col, end_row, end_col)
            } else {
                (end_row, end_col, start_row, start_col)
            };
            self.buffer.delete_range(sr, sc, er, ec + 1);
            self.cursor_row = sr;
            self.cursor_col = sc;
        }
    }

    pub fn yank_range(&mut self, start_row: usize, start_col: usize, end_row: usize, end_col: usize, linewise: bool) {
        if linewise {
            let (sr, er) = if start_row <= end_row {
                (start_row, end_row)
            } else {
                (end_row, start_row)
            };
            let mut content = String::new();
            for row in sr..=er {
                if let Some(line) = self.buffer.line(row) {
                    content.push_str(&line.content);
                    content.push('\n');
                }
            }
            self.default_register.content = content;
            self.default_register.linewise = true;
        } else {
            let (sr, sc, er, ec) = if start_row < end_row || (start_row == end_row && start_col <= end_col) {
                (start_row, start_col, end_row, end_col)
            } else {
                (end_row, end_col, start_row, start_col)
            };
            self.default_register.content = self.buffer.get_range(sr, sc, er, ec + 1);
            self.default_register.linewise = false;
        }
    }
}

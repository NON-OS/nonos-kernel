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

use crate::shell::editor::mode::SearchDirection;

use super::editor::Editor;

impl Editor {
    pub fn find_forward(&mut self, pattern: &str) -> bool {
        if let Some((row, col)) = self.buffer.find_forward(self.cursor_row, self.cursor_col, pattern) {
            self.set_cursor(row, col);
            true
        } else {
            false
        }
    }

    pub fn find_backward(&mut self, pattern: &str) -> bool {
        if let Some((row, col)) = self.buffer.find_backward(self.cursor_row, self.cursor_col, pattern) {
            self.set_cursor(row, col);
            true
        } else {
            false
        }
    }

    pub fn find_next(&mut self) -> bool {
        let pattern = self.mode_state.last_search.clone();
        if pattern.is_empty() {
            return false;
        }
        match self.mode_state.search_direction {
            SearchDirection::Forward => self.find_forward(&pattern),
            SearchDirection::Backward => self.find_backward(&pattern),
        }
    }

    pub fn find_prev(&mut self) -> bool {
        let pattern = self.mode_state.last_search.clone();
        if pattern.is_empty() {
            return false;
        }
        match self.mode_state.search_direction {
            SearchDirection::Forward => self.find_backward(&pattern),
            SearchDirection::Backward => self.find_forward(&pattern),
        }
    }

    pub fn page_down(&mut self, pages: usize) {
        let lines = pages * self.viewport_height;
        self.cursor_row = (self.cursor_row + lines).min(self.buffer.line_count().saturating_sub(1));
        self.ensure_cursor_visible();
    }

    pub fn page_up(&mut self, pages: usize) {
        let lines = pages * self.viewport_height;
        self.cursor_row = self.cursor_row.saturating_sub(lines);
        self.ensure_cursor_visible();
    }
}

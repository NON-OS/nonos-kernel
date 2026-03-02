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

use super::types::{LineEditor, MAX_INPUT_LEN};

impl LineEditor {
    pub fn insert_char(&mut self, ch: u8) {
        if self.length >= MAX_INPUT_LEN - 1 {
            return;
        }

        for i in (self.cursor_pos..self.length).rev() {
            self.buffer[i + 1] = self.buffer[i];
        }

        self.buffer[self.cursor_pos] = ch;
        self.length += 1;
        self.cursor_pos += 1;

        self.redraw();
    }

    pub fn delete_char(&mut self) {
        if self.cursor_pos >= self.length {
            return;
        }

        for i in self.cursor_pos..(self.length - 1) {
            self.buffer[i] = self.buffer[i + 1];
        }

        self.buffer[self.length - 1] = 0;
        self.length -= 1;

        self.redraw();
    }

    pub fn backspace(&mut self) {
        if self.cursor_pos == 0 {
            return;
        }

        self.cursor_pos -= 1;
        self.delete_char();
    }

    pub fn move_left(&mut self) {
        if self.cursor_pos > 0 {
            self.cursor_pos -= 1;
            self.update_cursor();
        }
    }

    pub fn move_right(&mut self) {
        if self.cursor_pos < self.length {
            self.cursor_pos += 1;
            self.update_cursor();
        }
    }

    pub fn move_home(&mut self) {
        self.cursor_pos = 0;
        self.update_cursor();
    }

    pub fn move_end(&mut self) {
        self.cursor_pos = self.length;
        self.update_cursor();
    }

    pub fn move_word_left(&mut self) {
        if self.cursor_pos == 0 {
            return;
        }

        self.cursor_pos -= 1;
        while self.cursor_pos > 0 && self.buffer[self.cursor_pos] == b' ' {
            self.cursor_pos -= 1;
        }
        while self.cursor_pos > 0 && self.buffer[self.cursor_pos - 1] != b' ' {
            self.cursor_pos -= 1;
        }

        self.update_cursor();
    }

    pub fn move_word_right(&mut self) {
        while self.cursor_pos < self.length && self.buffer[self.cursor_pos] != b' ' {
            self.cursor_pos += 1;
        }
        while self.cursor_pos < self.length && self.buffer[self.cursor_pos] == b' ' {
            self.cursor_pos += 1;
        }

        self.update_cursor();
    }

    pub fn delete_word_left(&mut self) {
        if self.cursor_pos == 0 {
            return;
        }

        let end = self.cursor_pos;
        while self.cursor_pos > 0 && self.buffer[self.cursor_pos - 1] == b' ' {
            self.cursor_pos -= 1;
        }
        while self.cursor_pos > 0 && self.buffer[self.cursor_pos - 1] != b' ' {
            self.cursor_pos -= 1;
        }

        let start = self.cursor_pos;
        let removed = end - start;

        for i in start..(self.length - removed) {
            self.buffer[i] = self.buffer[i + removed];
        }
        for i in (self.length - removed)..self.length {
            self.buffer[i] = 0;
        }

        self.length -= removed;
        self.redraw();
    }

    pub fn delete_to_end(&mut self) {
        for i in self.cursor_pos..self.length {
            self.buffer[i] = 0;
        }
        self.length = self.cursor_pos;
        self.redraw();
    }

    pub fn delete_to_start(&mut self) {
        if self.cursor_pos == 0 {
            return;
        }

        let removed = self.cursor_pos;
        for i in 0..(self.length - removed) {
            self.buffer[i] = self.buffer[i + removed];
        }
        for i in (self.length - removed)..self.length {
            self.buffer[i] = 0;
        }

        self.length -= removed;
        self.cursor_pos = 0;
        self.redraw();
    }

    pub fn clear_line(&mut self) {
        self.buffer = [0u8; MAX_INPUT_LEN];
        self.length = 0;
        self.cursor_pos = 0;
        self.redraw();
    }
}

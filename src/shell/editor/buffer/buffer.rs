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

use super::line::Line;

#[derive(Debug, Clone)]
pub struct Buffer {
    pub(crate) lines: Vec<Line>,
    pub(crate) filename: Option<String>,
    pub(crate) modified: bool,
    pub(crate) readonly: bool,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            lines: alloc::vec![Line::new()],
            filename: None,
            modified: false,
            readonly: false,
        }
    }

    pub fn from_string(content: &str) -> Self {
        let lines: Vec<Line> = if content.is_empty() {
            alloc::vec![Line::new()]
        } else {
            content.lines().map(Line::from_str).collect()
        };

        Self {
            lines: if lines.is_empty() {
                alloc::vec![Line::new()]
            } else {
                lines
            },
            filename: None,
            modified: false,
            readonly: false,
        }
    }

    pub fn from_file(filename: &str, content: &str) -> Self {
        let mut buffer = Self::from_string(content);
        buffer.filename = Some(String::from(filename));
        buffer
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn line(&self, idx: usize) -> Option<&Line> {
        self.lines.get(idx)
    }

    pub fn line_mut(&mut self, idx: usize) -> Option<&mut Line> {
        self.modified = true;
        self.lines.get_mut(idx)
    }

    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    pub fn set_filename(&mut self, filename: &str) {
        self.filename = Some(String::from(filename));
    }

    pub fn is_modified(&self) -> bool {
        self.modified
    }

    pub fn mark_saved(&mut self) {
        self.modified = false;
    }

    pub fn is_readonly(&self) -> bool {
        self.readonly
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
    }

    pub fn insert_char(&mut self, row: usize, col: usize, c: char) {
        if row < self.lines.len() {
            self.lines[row].insert_char(col, c);
            self.modified = true;
        }
    }

    pub fn delete_char(&mut self, row: usize, col: usize) -> Option<char> {
        if row < self.lines.len() {
            self.modified = true;
            self.lines[row].delete_char(col)
        } else {
            None
        }
    }

    pub fn insert_line(&mut self, idx: usize, line: Line) {
        if idx <= self.lines.len() {
            self.lines.insert(idx, line);
            self.modified = true;
        }
    }

    pub fn delete_line(&mut self, idx: usize) -> Option<Line> {
        if idx < self.lines.len() && self.lines.len() > 1 {
            self.modified = true;
            Some(self.lines.remove(idx))
        } else if idx < self.lines.len() {
            self.modified = true;
            let line = self.lines[idx].clone();
            self.lines[idx] = Line::new();
            Some(line)
        } else {
            None
        }
    }

    pub fn split_line(&mut self, row: usize, col: usize) {
        if row < self.lines.len() {
            let new_line = self.lines[row].split_at(col);
            self.lines.insert(row + 1, new_line);
            self.modified = true;
        }
    }

    pub fn join_lines(&mut self, row: usize) {
        if row + 1 < self.lines.len() {
            let next_line = self.lines.remove(row + 1);
            self.lines[row].append(&next_line);
            self.modified = true;
        }
    }

    pub fn insert_newline(&mut self, row: usize, col: usize) {
        self.split_line(row, col);
    }

    pub fn backspace(&mut self, row: usize, col: usize) -> (usize, usize) {
        if col > 0 {
            self.delete_char(row, col - 1);
            (row, col - 1)
        } else if row > 0 {
            let prev_len = self.lines[row - 1].char_count();
            self.join_lines(row - 1);
            (row - 1, prev_len)
        } else {
            (row, col)
        }
    }

    pub fn to_string(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.content.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn line_len(&self, row: usize) -> usize {
        self.lines.get(row).map(|l| l.char_count()).unwrap_or(0)
    }

    pub fn total_chars(&self) -> usize {
        self.lines.iter().map(|l| l.char_count() + 1).sum::<usize>() - 1
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

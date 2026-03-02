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

#[derive(Debug, Clone)]
pub struct Line {
    pub content: String,
}

impl Line {
    pub fn new() -> Self {
        Self {
            content: String::new(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        Self {
            content: String::from(s),
        }
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    pub fn char_count(&self) -> usize {
        self.content.chars().count()
    }

    pub fn insert_char(&mut self, idx: usize, c: char) {
        let byte_idx = self.char_to_byte_index(idx);
        self.content.insert(byte_idx, c);
    }

    pub fn delete_char(&mut self, idx: usize) -> Option<char> {
        if idx >= self.char_count() {
            return None;
        }
        let byte_idx = self.char_to_byte_index(idx);
        Some(self.content.remove(byte_idx))
    }

    pub fn split_at(&mut self, idx: usize) -> Line {
        let byte_idx = self.char_to_byte_index(idx);
        let rest = self.content.split_off(byte_idx);
        Line { content: rest }
    }

    pub fn append(&mut self, other: &Line) {
        self.content.push_str(&other.content);
    }

    pub fn char_at(&self, idx: usize) -> Option<char> {
        self.content.chars().nth(idx)
    }

    pub fn substring(&self, start: usize, end: usize) -> String {
        self.content.chars().skip(start).take(end - start).collect()
    }

    pub(crate) fn char_to_byte_index(&self, char_idx: usize) -> usize {
        self.content
            .char_indices()
            .nth(char_idx)
            .map(|(i, _)| i)
            .unwrap_or(self.content.len())
    }

    pub fn first_non_whitespace(&self) -> usize {
        self.content
            .chars()
            .position(|c| !c.is_whitespace())
            .unwrap_or(0)
    }

    pub fn last_non_whitespace(&self) -> usize {
        let count = self.char_count();
        if count == 0 {
            return 0;
        }

        for (i, c) in self.content.chars().rev().enumerate() {
            if !c.is_whitespace() {
                return count - 1 - i;
            }
        }
        0
    }

    pub fn indent_level(&self, tab_width: usize) -> usize {
        let mut level = 0;
        for c in self.content.chars() {
            match c {
                ' ' => level += 1,
                '\t' => level += tab_width,
                _ => break,
            }
        }
        level
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

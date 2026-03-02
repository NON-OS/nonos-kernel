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

use super::buffer::Buffer;

impl Buffer {
    pub fn find_forward(
        &self,
        start_row: usize,
        start_col: usize,
        pattern: &str,
    ) -> Option<(usize, usize)> {
        if pattern.is_empty() {
            return None;
        }

        for row in start_row..self.lines.len() {
            let line = &self.lines[row];
            let search_start = if row == start_row { start_col + 1 } else { 0 };

            if search_start < line.char_count() {
                let haystack: String = line.content.chars().skip(search_start).collect();
                if let Some(pos) = haystack.find(pattern) {
                    let char_pos: usize = haystack.chars().take(pos).count();
                    return Some((row, search_start + char_pos));
                }
            }
        }

        for row in 0..=start_row {
            let line = &self.lines[row];
            let search_end = if row == start_row {
                start_col
            } else {
                line.char_count()
            };

            let haystack: String = line.content.chars().take(search_end).collect();
            if let Some(pos) = haystack.find(pattern) {
                let char_pos: usize = haystack.chars().take(pos).count();
                return Some((row, char_pos));
            }
        }

        None
    }

    pub fn find_backward(
        &self,
        start_row: usize,
        start_col: usize,
        pattern: &str,
    ) -> Option<(usize, usize)> {
        if pattern.is_empty() {
            return None;
        }

        for row in (0..=start_row).rev() {
            let line = &self.lines[row];
            let search_end = if row == start_row {
                start_col
            } else {
                line.char_count()
            };

            let haystack: String = line.content.chars().take(search_end).collect();
            if let Some(pos) = haystack.rfind(pattern) {
                let char_pos: usize = haystack.chars().take(pos).count();
                return Some((row, char_pos));
            }
        }

        for row in (start_row..self.lines.len()).rev() {
            let line = &self.lines[row];
            if let Some(pos) = line.content.rfind(pattern) {
                let char_pos: usize = line.content.chars().take(pos).count();
                return Some((row, char_pos));
            }
        }

        None
    }
}

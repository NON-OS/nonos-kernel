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
    pub fn get_range(
        &self,
        start_row: usize,
        start_col: usize,
        end_row: usize,
        end_col: usize,
    ) -> String {
        if start_row == end_row {
            return self.lines[start_row].substring(start_col, end_col);
        }

        let mut result = String::new();

        let start_byte = self.lines[start_row].char_to_byte_index(start_col);
        result.push_str(&self.lines[start_row].content[start_byte..]);
        result.push('\n');

        for row in (start_row + 1)..end_row {
            result.push_str(&self.lines[row].content);
            result.push('\n');
        }

        if end_row < self.lines.len() {
            result.push_str(&self.lines[end_row].substring(0, end_col));
        }

        result
    }

    pub fn delete_range(
        &mut self,
        start_row: usize,
        start_col: usize,
        end_row: usize,
        end_col: usize,
    ) {
        if start_row == end_row {
            let line = &mut self.lines[start_row];
            let before: String = line.content.chars().take(start_col).collect();
            let after: String = line.content.chars().skip(end_col).collect();
            line.content = alloc::format!("{}{}", before, after);
        } else {
            let before: String = self.lines[start_row]
                .content
                .chars()
                .take(start_col)
                .collect();
            let after: String = self.lines[end_row].content.chars().skip(end_col).collect();

            self.lines[start_row].content = alloc::format!("{}{}", before, after);

            for _ in (start_row + 1)..=end_row {
                if start_row + 1 < self.lines.len() {
                    self.lines.remove(start_row + 1);
                }
            }
        }
        self.modified = true;
    }
}

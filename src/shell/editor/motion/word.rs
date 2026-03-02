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

use crate::shell::editor::buffer::Buffer;
use super::types::MotionResult;
use super::util::{is_whitespace, is_word_boundary};

pub fn motion_word_forward(buffer: &Buffer, mut row: usize, mut col: usize, count: u32, big_word: bool) -> MotionResult {
    for _ in 0..count {
        if let Some(line) = buffer.line(row) {
            let chars: alloc::vec::Vec<char> = line.content.chars().collect();

            while col < chars.len() && !is_word_boundary(&chars, col, big_word) {
                col += 1;
            }

            while col < chars.len() && is_whitespace(chars[col]) {
                col += 1;
            }

            if col >= chars.len() && row + 1 < buffer.line_count() {
                row += 1;
                col = 0;

                if let Some(next_line) = buffer.line(row) {
                    let next_chars: alloc::vec::Vec<char> = next_line.content.chars().collect();
                    while col < next_chars.len() && is_whitespace(next_chars[col]) {
                        col += 1;
                    }
                }
            }
        }
    }

    MotionResult::new(row, col)
}

pub fn motion_word_backward(buffer: &Buffer, mut row: usize, mut col: usize, count: u32, big_word: bool) -> MotionResult {
    for _ in 0..count {
        if col > 0 {
            col -= 1;
        } else if row > 0 {
            row -= 1;
            col = buffer.line_len(row).saturating_sub(1);
        }

        if let Some(line) = buffer.line(row) {
            let chars: alloc::vec::Vec<char> = line.content.chars().collect();

            while col > 0 && is_whitespace(chars[col]) {
                col -= 1;
            }

            while col > 0 && !is_word_boundary(&chars, col - 1, big_word) {
                col -= 1;
            }
        }
    }

    MotionResult::new(row, col)
}

pub fn motion_word_end(buffer: &Buffer, mut row: usize, mut col: usize, count: u32, big_word: bool) -> MotionResult {
    for _ in 0..count {
        if let Some(line) = buffer.line(row) {
            let chars: alloc::vec::Vec<char> = line.content.chars().collect();

            if col + 1 < chars.len() {
                col += 1;
            } else if row + 1 < buffer.line_count() {
                row += 1;
                col = 0;
            }

            if let Some(current_line) = buffer.line(row) {
                let current_chars: alloc::vec::Vec<char> = current_line.content.chars().collect();

                while col < current_chars.len() && is_whitespace(current_chars[col]) {
                    col += 1;
                }

                while col + 1 < current_chars.len() && !is_word_boundary(&current_chars, col, big_word) {
                    col += 1;
                }
            }
        }
    }

    MotionResult::new(row, col).inclusive()
}

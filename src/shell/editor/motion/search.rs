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

pub fn motion_paragraph_forward(buffer: &Buffer, mut row: usize, count: u32) -> MotionResult {
    for _ in 0..count {
        while row < buffer.line_count() && !buffer.line(row).map(|l| l.is_empty()).unwrap_or(true) {
            row += 1;
        }
        while row < buffer.line_count() && buffer.line(row).map(|l| l.is_empty()).unwrap_or(false) {
            row += 1;
        }
    }

    let row = row.min(buffer.line_count().saturating_sub(1));
    MotionResult::new(row, 0).linewise()
}

pub fn motion_paragraph_backward(buffer: &Buffer, mut row: usize, count: u32) -> MotionResult {
    for _ in 0..count {
        while row > 0 && !buffer.line(row).map(|l| l.is_empty()).unwrap_or(true) {
            row -= 1;
        }
        while row > 0 && buffer.line(row).map(|l| l.is_empty()).unwrap_or(false) {
            row -= 1;
        }
    }

    MotionResult::new(row, 0).linewise()
}

pub fn motion_matching_bracket(buffer: &Buffer, row: usize, col: usize) -> MotionResult {
    let line = match buffer.line(row) {
        Some(l) => l,
        None => return MotionResult::new(row, col),
    };

    let current_char = match line.char_at(col) {
        Some(c) => c,
        None => return MotionResult::new(row, col),
    };

    let (target, forward) = match current_char {
        '(' => (')', true),
        ')' => ('(', false),
        '[' => (']', true),
        ']' => ('[', false),
        '{' => ('}', true),
        '}' => ('{', false),
        '<' => ('>', true),
        '>' => ('<', false),
        _ => return MotionResult::new(row, col),
    };

    let mut depth = 1;
    let mut search_row = row;
    let mut search_col = col;

    loop {
        if forward {
            search_col += 1;
            if search_col >= buffer.line_len(search_row) {
                search_row += 1;
                search_col = 0;
            }
        } else {
            if search_col == 0 {
                if search_row == 0 {
                    break;
                }
                search_row -= 1;
                search_col = buffer.line_len(search_row).saturating_sub(1);
            } else {
                search_col -= 1;
            }
        }

        if search_row >= buffer.line_count() {
            break;
        }

        if let Some(search_line) = buffer.line(search_row) {
            if let Some(c) = search_line.char_at(search_col) {
                if c == current_char {
                    depth += 1;
                } else if c == target {
                    depth -= 1;
                    if depth == 0 {
                        return MotionResult::new(search_row, search_col);
                    }
                }
            }
        }
    }

    MotionResult::new(row, col)
}

pub fn motion_find_char(
    buffer: &Buffer,
    row: usize,
    col: usize,
    target: char,
    forward: bool,
    till: bool,
    count: u32,
) -> MotionResult {
    let line = match buffer.line(row) {
        Some(l) => l,
        None => return MotionResult::new(row, col),
    };

    let chars: alloc::vec::Vec<char> = line.content.chars().collect();
    let mut found_count = 0;
    let mut found_col = col;

    if forward {
        for i in (col + 1)..chars.len() {
            if chars[i] == target {
                found_count += 1;
                if found_count == count {
                    found_col = if till { i - 1 } else { i };
                    break;
                }
            }
        }
    } else {
        for i in (0..col).rev() {
            if chars[i] == target {
                found_count += 1;
                if found_count == count {
                    found_col = if till { i + 1 } else { i };
                    break;
                }
            }
        }
    }

    MotionResult::new(row, found_col).inclusive()
}

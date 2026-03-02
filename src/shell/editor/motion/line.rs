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

use crate::shell::editor::buffer::Buffer;
use super::types::MotionResult;

pub fn motion_line_start(row: usize) -> MotionResult {
    MotionResult::new(row, 0)
}

pub fn motion_line_end(buffer: &Buffer, row: usize) -> MotionResult {
    let line_len = buffer.line_len(row);
    let col = if line_len > 0 { line_len - 1 } else { 0 };
    MotionResult::new(row, col).inclusive()
}

pub fn motion_first_non_whitespace(buffer: &Buffer, row: usize) -> MotionResult {
    let col = buffer
        .line(row)
        .map(|l| l.first_non_whitespace())
        .unwrap_or(0);
    MotionResult::new(row, col)
}

pub fn motion_file_start() -> MotionResult {
    MotionResult::new(0, 0).linewise()
}

pub fn motion_file_end(buffer: &Buffer) -> MotionResult {
    let row = buffer.line_count().saturating_sub(1);
    MotionResult::new(row, 0).linewise()
}

pub fn motion_line_number(buffer: &Buffer, line: usize) -> MotionResult {
    let row = line.saturating_sub(1).min(buffer.line_count().saturating_sub(1));
    MotionResult::new(row, 0).linewise()
}

pub fn motion_screen_top(_row: usize) -> MotionResult {
    MotionResult::new(0, 0).linewise()
}

pub fn motion_screen_middle(buffer: &Buffer, _row: usize) -> MotionResult {
    let middle = buffer.line_count() / 2;
    MotionResult::new(middle, 0).linewise()
}

pub fn motion_screen_bottom(buffer: &Buffer, _row: usize) -> MotionResult {
    let bottom = buffer.line_count().saturating_sub(1);
    MotionResult::new(bottom, 0).linewise()
}

pub fn motion_column(buffer: &Buffer, row: usize, target_col: usize) -> MotionResult {
    let line_len = buffer.line_len(row);
    let col = target_col.min(if line_len > 0 { line_len - 1 } else { 0 });
    MotionResult::new(row, col)
}

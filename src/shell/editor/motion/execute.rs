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
use super::types::{Motion, MotionResult};
use super::word::{motion_word_forward, motion_word_backward, motion_word_end};
use super::line::{
    motion_line_start, motion_line_end, motion_first_non_whitespace,
    motion_file_start, motion_file_end, motion_line_number,
    motion_screen_top, motion_screen_middle, motion_screen_bottom, motion_column,
};
use super::search::{
    motion_paragraph_forward, motion_paragraph_backward,
    motion_matching_bracket, motion_find_char,
};

pub fn execute_motion(
    motion: Motion,
    buffer: &Buffer,
    row: usize,
    col: usize,
    count: u32,
) -> MotionResult {
    match motion {
        Motion::Left => motion_left(buffer, row, col, count),
        Motion::Right => motion_right(buffer, row, col, count),
        Motion::Up => motion_up(buffer, row, col, count),
        Motion::Down => motion_down(buffer, row, col, count),
        Motion::WordForward => motion_word_forward(buffer, row, col, count, false),
        Motion::WordBackward => motion_word_backward(buffer, row, col, count, false),
        Motion::WordEnd => motion_word_end(buffer, row, col, count, false),
        Motion::BigWordForward => motion_word_forward(buffer, row, col, count, true),
        Motion::BigWordBackward => motion_word_backward(buffer, row, col, count, true),
        Motion::BigWordEnd => motion_word_end(buffer, row, col, count, true),
        Motion::LineStart => motion_line_start(row),
        Motion::LineEnd => motion_line_end(buffer, row),
        Motion::FirstNonWhitespace => motion_first_non_whitespace(buffer, row),
        Motion::FileStart => motion_file_start(),
        Motion::FileEnd => motion_file_end(buffer),
        Motion::LineNumber(line) => motion_line_number(buffer, line),
        Motion::ScreenTop => motion_screen_top(row),
        Motion::ScreenMiddle => motion_screen_middle(buffer, row),
        Motion::ScreenBottom => motion_screen_bottom(buffer, row),
        Motion::ParagraphForward => motion_paragraph_forward(buffer, row, count),
        Motion::ParagraphBackward => motion_paragraph_backward(buffer, row, count),
        Motion::MatchingBracket => motion_matching_bracket(buffer, row, col),
        Motion::FindChar(c, forward) => motion_find_char(buffer, row, col, c, forward, false, count),
        Motion::TillChar(c, forward) => motion_find_char(buffer, row, col, c, forward, true, count),
        Motion::Column(c) => motion_column(buffer, row, c),
    }
}

fn motion_left(_buffer: &Buffer, row: usize, col: usize, count: u32) -> MotionResult {
    let new_col = col.saturating_sub(count as usize);
    MotionResult::new(row, new_col)
}

fn motion_right(buffer: &Buffer, row: usize, col: usize, count: u32) -> MotionResult {
    let line_len = buffer.line_len(row);
    let max_col = if line_len > 0 { line_len - 1 } else { 0 };
    let new_col = (col + count as usize).min(max_col);
    MotionResult::new(row, new_col)
}

fn motion_up(buffer: &Buffer, row: usize, col: usize, count: u32) -> MotionResult {
    let new_row = row.saturating_sub(count as usize);
    let line_len = buffer.line_len(new_row);
    let new_col = col.min(if line_len > 0 { line_len - 1 } else { 0 });
    MotionResult::new(new_row, new_col).linewise()
}

fn motion_down(buffer: &Buffer, row: usize, col: usize, count: u32) -> MotionResult {
    let new_row = (row + count as usize).min(buffer.line_count().saturating_sub(1));
    let line_len = buffer.line_len(new_row);
    let new_col = col.min(if line_len > 0 { line_len - 1 } else { 0 });
    MotionResult::new(new_row, new_col).linewise()
}

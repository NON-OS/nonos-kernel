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

use crate::shell::editor::mode::Mode;
use crate::shell::editor::motion::Motion;
use crate::shell::editor::state::Editor;

use super::types::{Key, InputResult};
use super::operators::execute_and_move;
use super::normal_ops::handle_normal_operators;

pub fn handle_normal_input(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Escape => {
            editor.mode_state_mut().reset_pending();
            InputResult::Continue
        }

        Key::Char(c) if c.is_ascii_digit() && (c != '0' || editor.mode_state().count.is_some()) => {
            if let Some(digit) = c.to_digit(10) {
                editor.mode_state_mut().accumulate_count(digit);
            }
            InputResult::Continue
        }

        Key::Char('i') => {
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('I') => {
            let row = editor.cursor_row();
            let col = editor.buffer().line(row).map(|l| l.first_non_whitespace()).unwrap_or(0);
            editor.set_cursor(row, col);
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('a') => {
            let row = editor.cursor_row();
            let col = editor.cursor_col();
            let line_len = editor.buffer().line_len(row);
            if col < line_len {
                editor.set_cursor(row, col + 1);
            }
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('A') => {
            let row = editor.cursor_row();
            let line_len = editor.buffer().line_len(row);
            editor.set_cursor(row, line_len);
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('o') => {
            let row = editor.cursor_row();
            editor.insert_line_below(row);
            editor.set_cursor(row + 1, 0);
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('O') => {
            let row = editor.cursor_row();
            editor.insert_line_above(row);
            editor.set_cursor(row, 0);
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('v') => {
            editor.start_visual(false);
            InputResult::Continue
        }

        Key::Char('V') => {
            editor.start_visual(true);
            InputResult::Continue
        }

        Key::Char(':') => {
            editor.mode_state_mut().set_mode(Mode::Command);
            InputResult::Continue
        }

        Key::Char('/') => {
            editor.mode_state_mut().set_mode(Mode::Search);
            editor.mode_state_mut().search_direction = crate::shell::editor::mode::SearchDirection::Forward;
            InputResult::Continue
        }

        Key::Char('?') => {
            editor.mode_state_mut().set_mode(Mode::Search);
            editor.mode_state_mut().search_direction = crate::shell::editor::mode::SearchDirection::Backward;
            InputResult::Continue
        }

        Key::Char('n') => {
            if editor.find_next() {
                InputResult::Continue
            } else {
                InputResult::Error(String::from("Pattern not found"))
            }
        }

        Key::Char('N') => {
            if editor.find_prev() {
                InputResult::Continue
            } else {
                InputResult::Error(String::from("Pattern not found"))
            }
        }

        Key::Char('h') | Key::Left => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::Left, count)
        }

        Key::Char('l') | Key::Right => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::Right, count)
        }

        Key::Char('j') | Key::Down => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::Down, count)
        }

        Key::Char('k') | Key::Up => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::Up, count)
        }

        Key::Char('w') => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::WordForward, count)
        }

        Key::Char('W') => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::BigWordForward, count)
        }

        Key::Char('b') => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::WordBackward, count)
        }

        Key::Char('B') => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::BigWordBackward, count)
        }

        Key::Char('e') => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::WordEnd, count)
        }

        Key::Char('E') => {
            let count = editor.mode_state().effective_count();
            execute_and_move(editor, Motion::BigWordEnd, count)
        }

        Key::Char('0') | Key::Home => execute_and_move(editor, Motion::LineStart, 1),
        Key::Char('$') | Key::End => execute_and_move(editor, Motion::LineEnd, 1),
        Key::Char('^') => execute_and_move(editor, Motion::FirstNonWhitespace, 1),
        Key::Char('g') => InputResult::Continue,

        Key::Char('G') => {
            let count = editor.mode_state().count;
            if let Some(line) = count {
                execute_and_move(editor, Motion::LineNumber(line as usize), 1)
            } else {
                execute_and_move(editor, Motion::FileEnd, 1)
            }
        }

        Key::Char('%') => execute_and_move(editor, Motion::MatchingBracket, 1),

        _ => handle_normal_operators(editor, key),
    }
}

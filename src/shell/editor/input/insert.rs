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

use crate::shell::editor::mode::Mode;
use crate::shell::editor::state::Editor;

use super::types::{Key, InputResult};

pub fn handle_insert_input(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Escape => {
            let col = editor.cursor_col();
            if col > 0 {
                editor.set_cursor(editor.cursor_row(), col - 1);
            }
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Char(c) => {
            editor.insert_char(c);
            InputResult::Continue
        }

        Key::Enter => {
            editor.insert_newline();
            InputResult::Continue
        }

        Key::Backspace => {
            editor.backspace();
            InputResult::Continue
        }

        Key::Delete => {
            editor.delete_char_at_cursor();
            InputResult::Continue
        }

        Key::Tab => {
            if editor.config().expand_tab {
                for _ in 0..editor.config().tab_width {
                    editor.insert_char(' ');
                }
            } else {
                editor.insert_char('\t');
            }
            InputResult::Continue
        }

        Key::Left => {
            let col = editor.cursor_col();
            if col > 0 {
                editor.set_cursor(editor.cursor_row(), col - 1);
            }
            InputResult::Continue
        }

        Key::Right => {
            let row = editor.cursor_row();
            let col = editor.cursor_col();
            let line_len = editor.buffer().line_len(row);
            if col < line_len {
                editor.set_cursor(row, col + 1);
            }
            InputResult::Continue
        }

        Key::Up => {
            let row = editor.cursor_row();
            if row > 0 {
                let col = editor.cursor_col();
                let new_len = editor.buffer().line_len(row - 1);
                editor.set_cursor(row - 1, col.min(new_len));
            }
            InputResult::Continue
        }

        Key::Down => {
            let row = editor.cursor_row();
            if row + 1 < editor.buffer().line_count() {
                let col = editor.cursor_col();
                let new_len = editor.buffer().line_len(row + 1);
                editor.set_cursor(row + 1, col.min(new_len));
            }
            InputResult::Continue
        }

        Key::Home => {
            editor.set_cursor(editor.cursor_row(), 0);
            InputResult::Continue
        }

        Key::End => {
            let row = editor.cursor_row();
            let line_len = editor.buffer().line_len(row);
            editor.set_cursor(row, line_len);
            InputResult::Continue
        }

        _ => InputResult::Continue,
    }
}

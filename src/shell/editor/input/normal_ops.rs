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

use crate::shell::editor::mode::{Mode, Operator};
use crate::shell::editor::state::Editor;

use super::types::{Key, InputResult};

pub fn handle_normal_operators(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Char('x') => {
            let count = editor.mode_state().effective_count();
            for _ in 0..count {
                editor.delete_char_at_cursor();
            }
            editor.mode_state_mut().reset_pending();
            InputResult::Continue
        }

        Key::Char('X') => {
            let count = editor.mode_state().effective_count();
            for _ in 0..count {
                editor.delete_char_before_cursor();
            }
            editor.mode_state_mut().reset_pending();
            InputResult::Continue
        }

        Key::Char('r') => {
            editor.mode_state_mut().set_mode(Mode::Replace);
            InputResult::Continue
        }

        Key::Char('d') => {
            if editor.mode_state().pending_operator == Some(Operator::Delete) {
                editor.delete_line();
                editor.mode_state_mut().reset_pending();
            } else {
                editor.mode_state_mut().pending_operator = Some(Operator::Delete);
            }
            InputResult::Continue
        }

        Key::Char('y') => {
            if editor.mode_state().pending_operator == Some(Operator::Yank) {
                editor.yank_line();
                editor.mode_state_mut().reset_pending();
            } else {
                editor.mode_state_mut().pending_operator = Some(Operator::Yank);
            }
            InputResult::Continue
        }

        Key::Char('c') => {
            if editor.mode_state().pending_operator == Some(Operator::Change) {
                editor.delete_line();
                editor.insert_line_at(editor.cursor_row());
                editor.mode_state_mut().set_mode(Mode::Insert);
            } else {
                editor.mode_state_mut().pending_operator = Some(Operator::Change);
            }
            InputResult::Continue
        }

        Key::Char('p') => {
            editor.paste_after();
            InputResult::Continue
        }

        Key::Char('P') => {
            editor.paste_before();
            InputResult::Continue
        }

        Key::Char('u') => {
            editor.undo();
            InputResult::Continue
        }

        Key::Ctrl('r') => {
            editor.redo();
            InputResult::Continue
        }

        Key::Char('.') => InputResult::Continue,

        Key::Ctrl('g') => {
            let row = editor.cursor_row() + 1;
            let total = editor.buffer().line_count();
            let filename = editor.buffer().filename().unwrap_or("[No Name]");
            let modified = if editor.buffer().is_modified() { " [+]" } else { "" };
            InputResult::Message(alloc::format!("\"{}\"{}  line {} of {}", filename, modified, row, total))
        }

        Key::PageDown | Key::Ctrl('f') => {
            let count = editor.mode_state().effective_count();
            editor.page_down(count as usize);
            editor.mode_state_mut().reset_pending();
            InputResult::Continue
        }

        Key::PageUp | Key::Ctrl('b') => {
            let count = editor.mode_state().effective_count();
            editor.page_up(count as usize);
            editor.mode_state_mut().reset_pending();
            InputResult::Continue
        }

        _ => InputResult::Continue,
    }
}

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

use crate::shell::editor::command::{execute_command, parse_command, CommandResult};
use crate::shell::editor::mode::Mode;
use crate::shell::editor::state::Editor;

use super::types::{Key, InputResult};

pub fn handle_command_input(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Escape => {
            editor.mode_state_mut().command_buffer.clear();
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Enter => {
            let command_str = editor.mode_state().command_buffer.clone();
            editor.mode_state_mut().set_mode(Mode::Normal);

            let cmd = parse_command(&command_str);
            match execute_command(editor, cmd) {
                CommandResult::Continue => InputResult::Continue,
                CommandResult::Quit => InputResult::Quit,
                CommandResult::Message(msg) => InputResult::Message(msg),
                CommandResult::Error(err) => InputResult::Error(err),
            }
        }

        Key::Backspace => {
            editor.mode_state_mut().command_buffer.pop();
            if editor.mode_state().command_buffer.is_empty() {
                editor.mode_state_mut().set_mode(Mode::Normal);
            }
            InputResult::Continue
        }

        Key::Char(c) => {
            editor.mode_state_mut().command_buffer.push(c);
            InputResult::Continue
        }

        _ => InputResult::Continue,
    }
}

pub fn handle_search_input(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Escape => {
            editor.mode_state_mut().search_buffer.clear();
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Enter => {
            let pattern = editor.mode_state().search_buffer.clone();
            editor.mode_state_mut().last_search = pattern.clone();
            editor.mode_state_mut().set_mode(Mode::Normal);

            let found = if editor.mode_state().search_direction == crate::shell::editor::mode::SearchDirection::Forward {
                editor.find_forward(&pattern)
            } else {
                editor.find_backward(&pattern)
            };

            if found {
                InputResult::Continue
            } else {
                InputResult::Error(alloc::format!("Pattern not found: {}", pattern))
            }
        }

        Key::Backspace => {
            editor.mode_state_mut().search_buffer.pop();
            InputResult::Continue
        }

        Key::Char(c) => {
            editor.mode_state_mut().search_buffer.push(c);
            InputResult::Continue
        }

        _ => InputResult::Continue,
    }
}

pub fn handle_replace_input(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Escape => {
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Char(c) => {
            editor.replace_char(c);
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        _ => {
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }
    }
}

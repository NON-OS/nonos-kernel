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
use crate::shell::editor::motion::Motion;
use crate::shell::editor::state::Editor;

use super::types::{Key, InputResult};
use super::operators::execute_and_move;

pub fn handle_visual_input(editor: &mut Editor, key: Key) -> InputResult {
    match key {
        Key::Escape => {
            editor.end_visual();
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Char('d') | Key::Char('x') => {
            editor.delete_selection();
            editor.end_visual();
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Char('y') => {
            editor.yank_selection();
            editor.end_visual();
            editor.mode_state_mut().set_mode(Mode::Normal);
            InputResult::Continue
        }

        Key::Char('c') => {
            editor.delete_selection();
            editor.end_visual();
            editor.mode_state_mut().set_mode(Mode::Insert);
            InputResult::Continue
        }

        Key::Char('h') | Key::Left => {
            execute_and_move(editor, Motion::Left, 1)
        }

        Key::Char('l') | Key::Right => {
            execute_and_move(editor, Motion::Right, 1)
        }

        Key::Char('j') | Key::Down => {
            execute_and_move(editor, Motion::Down, 1)
        }

        Key::Char('k') | Key::Up => {
            execute_and_move(editor, Motion::Up, 1)
        }

        Key::Char('w') => execute_and_move(editor, Motion::WordForward, 1),
        Key::Char('b') => execute_and_move(editor, Motion::WordBackward, 1),
        Key::Char('e') => execute_and_move(editor, Motion::WordEnd, 1),
        Key::Char('0') | Key::Home => execute_and_move(editor, Motion::LineStart, 1),
        Key::Char('$') | Key::End => execute_and_move(editor, Motion::LineEnd, 1),
        Key::Char('G') => execute_and_move(editor, Motion::FileEnd, 1),

        _ => InputResult::Continue,
    }
}

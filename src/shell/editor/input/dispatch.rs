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
use super::normal::handle_normal_input;
use super::insert::handle_insert_input;
use super::visual::handle_visual_input;
use super::command::{handle_command_input, handle_search_input, handle_replace_input};

pub fn handle_input(editor: &mut Editor, key: Key) -> InputResult {
    match editor.mode_state().mode {
        Mode::Normal => handle_normal_input(editor, key),
        Mode::Insert => handle_insert_input(editor, key),
        Mode::Visual | Mode::VisualLine | Mode::VisualBlock => handle_visual_input(editor, key),
        Mode::Command => handle_command_input(editor, key),
        Mode::Search => handle_search_input(editor, key),
        Mode::Replace => handle_replace_input(editor, key),
    }
}

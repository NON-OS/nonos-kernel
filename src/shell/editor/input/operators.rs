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

use crate::shell::editor::mode::{Mode, Operator};
use crate::shell::editor::motion::{execute_motion, Motion};
use crate::shell::editor::state::Editor;

use super::types::InputResult;

pub fn execute_and_move(editor: &mut Editor, motion: Motion, count: u32) -> InputResult {
    let row = editor.cursor_row();
    let col = editor.cursor_col();
    let result = execute_motion(motion, editor.buffer(), row, col, count);

    if let Some(op) = editor.mode_state().pending_operator {
        match op {
            Operator::Delete => {
                editor.delete_range(row, col, result.row, result.col, result.linewise);
            }
            Operator::Yank => {
                editor.yank_range(row, col, result.row, result.col, result.linewise);
            }
            Operator::Change => {
                editor.delete_range(row, col, result.row, result.col, result.linewise);
                editor.mode_state_mut().set_mode(Mode::Insert);
            }
            _ => {}
        }
        editor.mode_state_mut().reset_pending();
    } else {
        editor.set_cursor(result.row, result.col);
        if editor.mode_state().mode.is_visual() {
            editor.extend_visual(result.row, result.col);
        }
    }

    editor.mode_state_mut().reset_pending();
    InputResult::Continue
}

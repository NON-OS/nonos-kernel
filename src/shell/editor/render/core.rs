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
use alloc::vec::Vec;

use crate::shell::editor::mode::{Mode, SearchDirection};
use crate::shell::editor::state::Editor;

use super::types::{RenderConfig, RenderOutput, RenderedLine};
use super::util::{
    compute_display_col, compute_selection_range, digit_count, render_line_content,
};

pub fn render(editor: &Editor, config: &RenderConfig) -> RenderOutput {
    let buffer = editor.buffer();
    let viewport_row = editor.viewport_row();
    let viewport_height = config.height.saturating_sub(2);

    let gutter_width = if editor.config().show_line_numbers {
        let max_line = buffer.line_count();
        digit_count(max_line) + 1
    } else {
        0
    };

    let text_width = config.width.saturating_sub(gutter_width);

    let mut lines = Vec::with_capacity(viewport_height);
    let cursor_row = editor.cursor_row();
    let cursor_col = editor.cursor_col();

    for screen_row in 0..viewport_height {
        let buffer_row = viewport_row + screen_row;

        if let Some(line) = buffer.line(buffer_row) {
            let is_current = buffer_row == cursor_row;

            let line_num = if editor.config().show_line_numbers {
                if editor.config().relative_numbers && !is_current {
                    let diff = if buffer_row > cursor_row {
                        buffer_row - cursor_row
                    } else {
                        cursor_row - buffer_row
                    };
                    Some(diff)
                } else {
                    Some(buffer_row + 1)
                }
            } else {
                None
            };

            let (sel_start, sel_end) = if let Some(sel) = editor.visual_selection() {
                compute_selection_range(buffer_row, sel)
            } else {
                (None, None)
            };

            let display_content =
                render_line_content(&line.content, text_width, editor.config().tab_width);

            lines.push(RenderedLine {
                content: display_content,
                line_number: line_num,
                is_current,
                selection_start: sel_start,
                selection_end: sel_end,
            });
        } else {
            lines.push(RenderedLine {
                content: String::from("~"),
                line_number: None,
                is_current: false,
                selection_start: None,
                selection_end: None,
            });
        }
    }

    let status_line = render_status_line(editor, config.width);
    let command_line = render_command_line(editor);

    let cursor_x = gutter_width
        + compute_display_col(
            buffer
                .line(cursor_row)
                .map(|l| l.content.as_str())
                .unwrap_or(""),
            cursor_col,
            editor.config().tab_width,
        );
    let cursor_y = cursor_row.saturating_sub(viewport_row);

    RenderOutput {
        lines,
        status_line,
        command_line,
        cursor_x,
        cursor_y,
    }
}

fn render_status_line(editor: &Editor, width: usize) -> String {
    let buffer = editor.buffer();
    let filename = buffer.filename().unwrap_or("[No Name]");
    let modified = if buffer.is_modified() { " [+]" } else { "" };
    let readonly = if buffer.is_readonly() { " [RO]" } else { "" };

    let left = alloc::format!(" {}{}{}", filename, modified, readonly);

    let row = editor.cursor_row() + 1;
    let col = editor.cursor_col() + 1;
    let total_lines = buffer.line_count();
    let percent = if total_lines == 0 {
        100
    } else {
        (row * 100) / total_lines
    };

    let right = alloc::format!("{}% {}:{} ", percent, row, col);

    let padding = width.saturating_sub(left.len() + right.len());
    let spaces: String = (0..padding).map(|_| ' ').collect();

    alloc::format!("{}{}{}", left, spaces, right)
}

fn render_command_line(editor: &Editor) -> String {
    let mode_state = editor.mode_state();

    match mode_state.mode {
        Mode::Command => {
            let prefix = ":";
            alloc::format!("{}{}", prefix, mode_state.command_buffer)
        }
        Mode::Search => {
            let prefix = if mode_state.search_direction == SearchDirection::Forward {
                "/"
            } else {
                "?"
            };
            alloc::format!("{}{}", prefix, mode_state.search_buffer)
        }
        _ => {
            if let Some(msg) = editor.message() {
                String::from(msg)
            } else {
                String::from(mode_state.mode.status_indicator())
            }
        }
    }
}

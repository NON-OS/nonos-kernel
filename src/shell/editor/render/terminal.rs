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

use crate::shell::editor::state::Editor;
use crate::shell::terminal::{clear_content, clear_row, draw_cursor, draw_text_at};
use crate::shell::terminal::{COLOR_ERROR, COLOR_SUCCESS, COLOR_TEXT, COLOR_TEXT_DIM};

use super::types::RenderConfig;
use super::util::digit_count;
use super::core::render;

pub fn render_to_terminal(editor: &Editor, config: &RenderConfig) {
    let output = render(editor, config);

    clear_content();

    let gutter_width = if editor.config().show_line_numbers {
        digit_count(editor.buffer().line_count()) + 1
    } else {
        0
    };

    for (y, line) in output.lines.iter().enumerate() {
        clear_row(y as u32);

        if let Some(num) = line.line_number {
            let num_str = alloc::format!("{:>width$} ", num, width = gutter_width - 1);
            draw_text_at(0, y as u32, num_str.as_bytes(), COLOR_TEXT_DIM);
        }

        let text_col = gutter_width as u32;
        draw_text_at(text_col, y as u32, line.content.as_bytes(), COLOR_TEXT);
    }

    let status_y = (config.height - 2) as u32;
    draw_text_at(0, status_y, output.status_line.as_bytes(), COLOR_SUCCESS);

    let cmd_y = (config.height - 1) as u32;
    let cmd_color = if editor.is_error() {
        COLOR_ERROR
    } else {
        COLOR_TEXT
    };
    draw_text_at(0, cmd_y, output.command_line.as_bytes(), cmd_color);

    draw_cursor(output.cursor_x as u32, output.cursor_y as u32, true);
}

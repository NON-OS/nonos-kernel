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

use crate::shell::editor::state::VisualSelection;

pub fn render_line_content(content: &str, max_width: usize, tab_width: usize) -> String {
    let mut result = String::with_capacity(max_width);
    let mut col = 0;

    for c in content.chars() {
        if col >= max_width {
            break;
        }

        match c {
            '\t' => {
                let spaces = tab_width - (col % tab_width);
                for _ in 0..spaces {
                    if col < max_width {
                        result.push(' ');
                        col += 1;
                    }
                }
            }
            _ => {
                result.push(c);
                col += 1;
            }
        }
    }

    result
}

pub fn compute_display_col(content: &str, char_col: usize, tab_width: usize) -> usize {
    let mut display_col = 0;
    for (i, c) in content.chars().enumerate() {
        if i >= char_col {
            break;
        }
        match c {
            '\t' => {
                display_col += tab_width - (display_col % tab_width);
            }
            _ => {
                display_col += 1;
            }
        }
    }
    display_col
}

pub fn compute_selection_range(
    row: usize,
    sel: &VisualSelection,
) -> (Option<usize>, Option<usize>) {
    let (start_row, start_col, end_row, end_col) = if sel.start_row < sel.end_row
        || (sel.start_row == sel.end_row && sel.start_col <= sel.end_col)
    {
        (sel.start_row, sel.start_col, sel.end_row, sel.end_col)
    } else {
        (sel.end_row, sel.end_col, sel.start_row, sel.start_col)
    };

    if sel.line_wise {
        if row >= start_row && row <= end_row {
            (Some(0), Some(usize::MAX))
        } else {
            (None, None)
        }
    } else if row < start_row || row > end_row {
        (None, None)
    } else if row == start_row && row == end_row {
        (Some(start_col), Some(end_col))
    } else if row == start_row {
        (Some(start_col), Some(usize::MAX))
    } else if row == end_row {
        (Some(0), Some(end_col))
    } else {
        (Some(0), Some(usize::MAX))
    }
}

pub fn digit_count(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut count = 0;
    let mut num = n;
    while num > 0 {
        count += 1;
        num /= 10;
    }
    count
}

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

#[derive(Debug, Clone)]
pub struct EditorConfig {
    pub show_line_numbers: bool,
    pub relative_numbers: bool,
    pub tab_width: usize,
    pub expand_tab: bool,
    pub auto_indent: bool,
    pub show_matching: bool,
    pub ignore_case: bool,
    pub smart_case: bool,
    pub wrap_lines: bool,
    pub scroll_offset: usize,
}

impl Default for EditorConfig {
    fn default() -> Self {
        Self {
            show_line_numbers: true,
            relative_numbers: false,
            tab_width: 4,
            expand_tab: true,
            auto_indent: true,
            show_matching: true,
            ignore_case: false,
            smart_case: true,
            wrap_lines: false,
            scroll_offset: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VisualSelection {
    pub start_row: usize,
    pub start_col: usize,
    pub end_row: usize,
    pub end_col: usize,
    pub line_wise: bool,
}

#[derive(Debug, Clone)]
pub struct Register {
    pub content: String,
    pub linewise: bool,
}

impl Register {
    pub fn new() -> Self {
        Self {
            content: String::new(),
            linewise: false,
        }
    }
}

impl Default for Register {
    fn default() -> Self {
        Self::new()
    }
}

pub fn normalize_selection(sel: &VisualSelection) -> (usize, usize, usize, usize) {
    if sel.start_row < sel.end_row || (sel.start_row == sel.end_row && sel.start_col <= sel.end_col) {
        (sel.start_row, sel.start_col, sel.end_row, sel.end_col)
    } else {
        (sel.end_row, sel.end_col, sel.start_row, sel.start_col)
    }
}

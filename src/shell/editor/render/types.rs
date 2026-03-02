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

#[derive(Debug, Clone)]
pub struct RenderConfig {
    pub width: usize,
    pub height: usize,
    pub color_scheme: ColorScheme,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            width: 80,
            height: 24,
            color_scheme: ColorScheme::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ColorScheme {
    pub text: u32,
    pub background: u32,
    pub line_number: u32,
    pub cursor: u32,
    pub selection: u32,
    pub status_line: u32,
    pub status_text: u32,
    pub error: u32,
    pub search_match: u32,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            text: 0xFFFFFF,
            background: 0x1E1E1E,
            line_number: 0x858585,
            cursor: 0xFFFFFF,
            selection: 0x264F78,
            status_line: 0x007ACC,
            status_text: 0xFFFFFF,
            error: 0xFF5555,
            search_match: 0xFFFF00,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenderOutput {
    pub lines: Vec<RenderedLine>,
    pub status_line: String,
    pub command_line: String,
    pub cursor_x: usize,
    pub cursor_y: usize,
}

#[derive(Debug, Clone)]
pub struct RenderedLine {
    pub content: String,
    pub line_number: Option<usize>,
    pub is_current: bool,
    pub selection_start: Option<usize>,
    pub selection_end: Option<usize>,
}

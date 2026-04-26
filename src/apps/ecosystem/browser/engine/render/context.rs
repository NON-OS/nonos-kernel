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
use crate::apps::ecosystem::browser::engine::types::{RenderLine, RenderElement, TextStyle};

const MAX_RENDER_LINES: usize = 512;

pub(super) struct RenderContext {
    pub lines: Vec<RenderLine>,
    pub links: Vec<(u32, u32, u32, u32, String)>,
    pub current_y: u32,
    pub current_x: u32,
    pub current_line_elements: Vec<RenderElement>,
    pub style_stack: Vec<TextStyle>,
    pub current_style: TextStyle,
    pub indent_level: u32,
    pub line_height: u32,
    pub char_width: u32,
    pub margin: u32,
    pub usable_width: u32,
    pub indent_px: u32,
    pub base_url: String,
    pub form_action: Option<String>,
    pub form_method: Option<String>,
}

impl RenderContext {
    pub(super) fn new(viewport_width: u32, base_url: String) -> Self {
        let margin = 10u32;
        Self {
            lines: Vec::new(),
            links: Vec::new(),
            current_y: 0,
            current_x: 0,
            current_line_elements: Vec::new(),
            style_stack: Vec::new(),
            current_style: TextStyle::default(),
            indent_level: 0,
            line_height: 20,
            char_width: 8,
            margin,
            usable_width: viewport_width.saturating_sub(margin * 2),
            indent_px: 30,
            base_url,
            form_action: None,
            form_method: None,
        }
    }

    pub(super) fn flush_line(&mut self) {
        if !self.current_line_elements.is_empty() {
            if self.lines.len() >= MAX_RENDER_LINES {
                self.current_line_elements.clear();
                self.current_x = 0;
                return;
            }
            self.lines.push(RenderLine {
                y: self.current_y,
                elements: core::mem::take(&mut self.current_line_elements),
            });
            self.current_y += self.line_height;
            self.current_x = 0;
        }
    }

    pub(super) fn is_full(&self) -> bool {
        self.lines.len() >= MAX_RENDER_LINES
    }
}

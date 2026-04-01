// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::gop::get_dimensions;

const MARGIN: u32 = 40;
const HEADER_HEIGHT: u32 = 100;

pub struct TerminalLayout {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub content_x: u32,
    pub content_y: u32,
    pub content_width: u32,
    pub content_height: u32,
}

impl TerminalLayout {
    pub fn compute() -> Self {
        let (screen_w, screen_h) = get_dimensions();
        let width = screen_w - (MARGIN * 2);
        let height = screen_h - (MARGIN * 2);
        let x = MARGIN;
        let y = MARGIN;

        Self {
            x,
            y,
            width,
            height,
            content_x: x + 20,
            content_y: y + HEADER_HEIGHT,
            content_width: width - 40,
            content_height: height - HEADER_HEIGHT - 20,
        }
    }

    pub fn max_visible_lines(&self) -> usize {
        (self.content_height / 16) as usize
    }
}

pub fn draw_terminal_frame(_layout: &TerminalLayout) {}

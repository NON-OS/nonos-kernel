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

const MARGIN: u32 = 30;
const HEADER_HEIGHT: u32 = 32;

pub struct RightPanelLayout {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub content_x: u32,
    pub content_y: u32,
}

impl RightPanelLayout {
    pub fn compute() -> Self {
        let (screen_w, screen_h) = get_dimensions();
        let x = (screen_w / 2) + (MARGIN / 2);
        let width = (screen_w / 2) - MARGIN - (MARGIN / 2);
        let height = screen_h - (MARGIN * 2);

        Self {
            x,
            y: MARGIN,
            width,
            height,
            content_x: x + 16,
            content_y: MARGIN + HEADER_HEIGHT + 8,
        }
    }
}

pub fn draw_right_panel_frame(_layout: &RightPanelLayout) {}

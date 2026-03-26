// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::framebuffer::fill_rect;
use super::constants::*;
use super::primitives::draw_rounded_rect;

pub(super) fn draw_window_frame(x: u32, y: u32, w: u32, h: u32, focused: bool) {
    let bg = if focused { WIN_BG_FOCUSED } else { WIN_BG_UNFOCUSED };
    draw_rounded_rect(x, y, w, h, CORNER_RADIUS, bg);
    if focused {
        draw_border_glow(x, y, w, h);
    }
}

fn draw_border_glow(x: u32, y: u32, w: u32, h: u32) {
    for i in 0..2u32 {
        let alpha = 12 - i * 5;
        let top_w = w.saturating_sub(CORNER_RADIUS * 2);
        let side_h = h.saturating_sub(CORNER_RADIUS * 2);
        fill_rect(x + CORNER_RADIUS, y + i, top_w, 1, (alpha << 24) | 0xFFFFFF);
        fill_rect(x + i, y + CORNER_RADIUS, 1, side_h, (alpha << 24) | 0xFFFFFF);
    }
    for i in 0..2u32 {
        let alpha = 8 - i * 3;
        let bot_w = w.saturating_sub(CORNER_RADIUS * 2);
        let side_h = h.saturating_sub(CORNER_RADIUS * 2);
        fill_rect(x + CORNER_RADIUS, y + h - 1 - i, bot_w, 1, (alpha << 24) | 0x000000);
        fill_rect(x + w - 1 - i, y + CORNER_RADIUS, 1, side_h, (alpha << 24) | 0x000000);
    }
}

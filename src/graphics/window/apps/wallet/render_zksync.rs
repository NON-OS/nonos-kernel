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

use super::render::{COLOR_ACCENT, COLOR_BG, COLOR_CARD, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use super::render_views::draw_rounded_rect;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;

pub(super) fn draw_zksync_view(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_string(x + 20, y + 20, b"ZkSync Era (Layer 2)", COLOR_TEXT_WHITE);
    for shadow in 0..4u32 {
        draw_rounded_rect(
            x + 20 + shadow / 2,
            y + 50 + shadow + 2,
            w - 40,
            120,
            14,
            ((15 - shadow * 3) << 24) | 0x000000,
        );
    }
    draw_rounded_rect(x + 20, y + 50, w - 40, 120, 14, COLOR_CARD);
    draw_string(x + 36, y + 70, b"L2 Balance", COLOR_TEXT_DIM);
    draw_string(x + 36, y + 92, b"0.00", COLOR_TEXT_WHITE);
    draw_string(x + 76, y + 92, b"ETH", 0xFF8B5CF6);
    draw_string(x + 36, y + 120, b"Chain ID: 324 (Era Mainnet)", COLOR_TEXT_DIM);
    draw_string(x + 36, y + 140, b"Status: Connected", 0xFF34C759);
    for shadow in 0..4u32 {
        draw_rounded_rect(
            x + 20 + shadow / 2,
            y + 185 + shadow + 2,
            w - 40,
            100,
            14,
            ((15 - shadow * 3) << 24) | 0x000000,
        );
    }
    draw_rounded_rect(x + 20, y + 185, w - 40, 100, 14, COLOR_CARD);
    draw_string(x + 36, y + 205, b"Actions", COLOR_TEXT_WHITE);
    draw_rounded_rect(x + 36, y + 230, 100, 36, 8, 0xFF8B5CF6);
    draw_string(x + 52, y + 240, b"Bridge", 0xFF000000);
    draw_rounded_rect(x + 150, y + 230, 100, 36, 8, COLOR_ACCENT);
    draw_string(x + 170, y + 240, b"Send", 0xFF000000);
    draw_rounded_rect(x + 264, y + 230, 100, 36, 8, 0xFF34C759);
    draw_string(x + 276, y + 240, b"Receive", 0xFF000000);
}

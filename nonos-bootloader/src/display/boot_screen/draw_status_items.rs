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

use crate::graphics::framebuffer::{draw_filled_rect, draw_text};
use crate::graphics::colors::{RGB, WHITE};

pub fn draw_status_items(x: u32, y: u32) {
    let success_color = RGB { r: 0x00, g: 0xD4, b: 0x69 };
    let item_spacing = 150;

    let items = [
        ("SecureBoot", true),
        ("TPM 2.0", true),
        ("UEFI Mode", true),
        ("Verified", true),
    ];

    for (i, (label, enabled)) in items.iter().enumerate() {
        let item_x = x + i as u32 * item_spacing;
        let color = if *enabled { success_color } else { RGB { r: 0xF4, g: 0x43, b: 0x36 } };
        let status = if *enabled { "✓" } else { "✗" };

        draw_filled_rect(item_x, y, 12, 12, color);
        draw_text(item_x + 2, y + 2, status, WHITE, 1);
        draw_text(item_x + 20, y + 2, label, WHITE, 1);
    }
}
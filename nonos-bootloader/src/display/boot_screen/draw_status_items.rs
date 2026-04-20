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

use crate::display::gop::fill_rect;
use crate::display::font::draw_string;
use crate::display::constants::COLOR_TEXT_WHITE;


pub fn draw_status_items(x: u32, y: u32) {
    let success_color = 0xFF00D469u32;
    let error_color = 0xFFF44336u32;
    let item_spacing = 150;

    let items: &[(&[u8], bool)] = &[
        (b"SecureBoot", true),
        (b"TPM 2.0", true),
        (b"UEFI Mode", true),
        (b"Verified", true),
    ];

    for (i, (label, enabled)) in items.iter().enumerate() {
        let item_x = x + i as u32 * item_spacing;
        let color = if *enabled { success_color } else { error_color };
        let status = if *enabled { b"\xE2\x9C\x93" } else { b"\xE2\x9C\x97" };

        fill_rect(item_x, y, 12, 12, color);
        draw_string(item_x + 2, y + 2, status, COLOR_TEXT_WHITE);
        draw_string(item_x + 20, y + 2, *label, COLOR_TEXT_WHITE);
    }
}
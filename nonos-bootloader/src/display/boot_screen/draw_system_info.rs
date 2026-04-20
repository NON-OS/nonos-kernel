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

use crate::display::font::draw_string;


pub fn draw_system_info(width: u32, height: u32) {
    let info_color = 0xFF787878u32;
    let success_color = 0xFF4CAF50u32;
    let footer_y = height - 40;

    draw_string(20, footer_y, b"NONOS Bootloader v2.1.0", info_color);
    draw_string(20, footer_y + 15, b"UEFI Secure Boot: ENABLED", success_color);

    if width > 250 {
        draw_string(width - 250, footer_y, b"Build: 2026.04.20", info_color);
        draw_string(width - 250, footer_y + 15, b"Target: x86_64-nonos", info_color);
    }
}
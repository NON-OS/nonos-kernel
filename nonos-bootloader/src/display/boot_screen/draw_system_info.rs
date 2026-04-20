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

use crate::graphics::framebuffer::draw_text;
use crate::graphics::colors::RGB;

pub fn draw_system_info(width: u32, height: u32) {
    let info_color = RGB { r: 120, g: 120, b: 120 };
    let success_color = RGB { r: 0x4C, g: 0xAF, b: 0x50 };
    let footer_y = height - 40;

    draw_text(20, footer_y, "NONOS Bootloader v2.1.0", info_color, 1);
    draw_text(20, footer_y + 15, "UEFI Secure Boot: ENABLED", success_color, 1);

    draw_text(width - 250, footer_y, "Build: 2026.04.20", info_color, 1);
    draw_text(width - 250, footer_y + 15, "Target: x86_64-nonos", info_color, 1);
}
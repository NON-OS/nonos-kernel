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

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::window::settings::render::draw_string;

pub(super) fn draw_system_info(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 225, b"System Information", COLOR_ACCENT);
    fill_rect(x + 15, y + 245, w - 30, 80, 0xFF1A1F26);
    draw_string(x + 25, y + 255, b"OS:", 0xFF7D8590);
    draw_string(x + 80, y + 255, b"N\\xd8NOS ZeroState v0.8.3", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 273, b"Arch:", 0xFF7D8590);
    draw_string(x + 80, y + 273, b"x86_64 UEFI", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 291, b"Memory:", 0xFF7D8590);
    draw_string(x + 80, y + 291, b"RAM-only (volatile)", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 309, b"Kernel:", 0xFF7D8590);
    draw_string(x + 80, y + 309, b"Ed25519 Verified", COLOR_GREEN);
}

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
use crate::graphics::backgrounds::get_background;
use crate::graphics::window::settings::render::draw_string;
use super::slider::draw_bg_name;

pub(super) fn draw_background_selector(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 275, b"Desktop Background", COLOR_ACCENT);
    let bg = get_background();
    fill_rect(x + 15, y + 295, w - 30, 36, 0xFF1A1F26);
    fill_rect(x + 20, y + 300, 26, 26, 0xFF2D333B);
    draw_string(x + 28, y + 305, b"<", COLOR_TEXT_WHITE);
    draw_bg_name(x + 60, y + 306, bg.name());
    fill_rect(x + w - 46, y + 300, 26, 26, 0xFF2D333B);
    draw_string(x + w - 38, y + 305, b">", COLOR_TEXT_WHITE);
}

pub(super) fn draw_system_info(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y + 345, b"System Information", COLOR_ACCENT);
    fill_rect(x + 15, y + 365, w - 30, 80, 0xFF1A1F26);
    draw_string(x + 25, y + 375, b"OS:", 0xFF7D8590);
    draw_string(x + 80, y + 375, b"N\\xd8NOS ZeroState v0.8.3", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 393, b"Arch:", 0xFF7D8590);
    draw_string(x + 80, y + 393, b"x86_64 UEFI", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 411, b"Memory:", 0xFF7D8590);
    draw_string(x + 80, y + 411, b"RAM-only (volatile)", COLOR_TEXT_WHITE);
    draw_string(x + 25, y + 429, b"Kernel:", 0xFF7D8590);
    draw_string(x + 80, y + 429, b"Ed25519 Verified", COLOR_GREEN);
}

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

use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE};
use super::main::draw_string;
use crate::graphics::window::settings::state::{PAGE_PRIVACY, PAGE_NETWORK, PAGE_APPEARANCE, PAGE_SYSTEM, PAGE_POWER};

pub(super) fn draw_header(x: u32, y: u32, w: u32, page: u8) {
    fill_rect(x, y, w, 50, 0xFF1E1E24);
    let header: &[u8] = match page {
        PAGE_PRIVACY => b"Privacy",
        PAGE_NETWORK => b"Network",
        PAGE_APPEARANCE => b"Wallpapers",
        PAGE_SYSTEM => b"System",
        PAGE_POWER => b"Power",
        _ => b"System",
    };
    draw_string(x + 20, y + 18, header, COLOR_TEXT_WHITE);
    fill_rect(x, y + 49, w, 1, 0xFF2C2C30);
}

pub(super) fn draw_footer(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y + h - 40, w, 1, 0xFF2C2C30);
    fill_rect(x, y + h - 39, w, 39, 0xFF16161A);
    draw_string(x + 20, y + h - 26, b"N\xd8NOS", 0xFF3B82F6);
    draw_string(x + 68, y + h - 26, b"v1.0.0", 0xFF4B5563);
    draw_string(x + w - 140, y + h - 26, b"ZeroState Mode", 0xFF34D399);
}

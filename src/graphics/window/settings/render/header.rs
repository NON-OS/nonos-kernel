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

use super::main::draw_string;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::settings::state::*;

const BG_HEADER: u32 = 0xFF161B22;
const BG_FOOTER: u32 = 0xFF0D1117;
const TEXT_PRIMARY: u32 = 0xFFE6EDF3;
const TEXT_DIM: u32 = 0xFF7D8590;
const ACCENT: u32 = 0xFF3B82F6;
const SUCCESS: u32 = 0xFF10B981;
const BORDER: u32 = 0xFF30363D;

pub(super) fn draw_header(x: u32, y: u32, w: u32, page: u8) {
    fill_rect(x, y, w, 60, BG_HEADER);
    let (title, desc): (&[u8], &[u8]) = match page {
        PAGE_PRIVACY => (b"Privacy & Security", b"Control your anonymity and data"),
        PAGE_NETWORK => (b"Network", b"Manage WiFi, Ethernet, and DNS"),
        PAGE_APPEARANCE => (b"Appearance", b"Customize theme and wallpaper"),
        PAGE_SYSTEM => (b"System", b"Display, input, and preferences"),
        PAGE_POWER => (b"Power", b"Shutdown, reboot, and power states"),
        _ => (b"System", b"Configure your preferences"),
    };
    draw_string(x + 24, y + 16, title, TEXT_PRIMARY);
    draw_string(x + 24, y + 36, desc, TEXT_DIM);
    fill_rect(x, y + 59, w, 1, BORDER);
}

pub(super) fn draw_footer(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y + h - 36, w, 1, BORDER);
    fill_rect(x, y + h - 35, w, 35, BG_FOOTER);
    draw_string(x + 20, y + h - 22, b"N\xd8NOS", ACCENT);
    draw_string(x + 64, y + h - 22, b"v1.0.0", TEXT_DIM);
    draw_string(x + w - 110, y + h - 22, b"ZeroState", SUCCESS);
}

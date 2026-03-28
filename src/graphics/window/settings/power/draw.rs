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

use crate::graphics::framebuffer::fill_rounded_rect;
use crate::graphics::window::settings::render::draw_string;

const BG_CARD: u32 = 0xFF161B22;
const BG_DANGER: u32 = 0xFFDC2626;
const BG_PRIMARY: u32 = 0xFF1F6FEB;
const BG_STATE: u32 = 0xFF21262D;
const TEXT: u32 = 0xFFE6EDF3;
const TEXT_DIM: u32 = 0xFF7D8590;
const SUCCESS: u32 = 0xFF10B981;
const WARNING: u32 = 0xFFF59E0B;
const ERROR: u32 = 0xFFEF4444;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    fill_rounded_rect(x + 16, y, w - 32, 80, 8, BG_CARD);
    draw_string(x + 28, y + 12, b"Power Actions", TEXT);
    draw_string(x + 28, y + 28, b"All data will be lost on power action", WARNING);
    fill_rounded_rect(x + 28, y + 48, 120, 24, 4, BG_DANGER);
    draw_string(x + 48, y + 53, b"Shutdown", TEXT);
    fill_rounded_rect(x + 156, y + 48, 100, 24, 4, BG_PRIMARY);
    draw_string(x + 180, y + 53, b"Reboot", TEXT);
    fill_rounded_rect(x + 16, y + 90, w - 32, 130, 8, BG_CARD);
    draw_string(x + 28, y + 102, b"Power States (ACPI)", TEXT);
    draw_state(x + 28, y + 124, w - 56, b"S0 Working", b"ACTIVE", SUCCESS);
    draw_state(x + 28, y + 146, w - 56, b"S1 Standby", b"BLOCKED", ERROR);
    draw_state(x + 28, y + 168, w - 56, b"S3 Suspend", b"BLOCKED", ERROR);
    draw_state(x + 28, y + 190, w - 56, b"S5 Soft Off", b"AVAILABLE", SUCCESS);
    fill_rounded_rect(x + 16, y + 230, w - 32, 100, 8, BG_CARD);
    draw_string(x + 28, y + 242, b"ZeroState Security", TEXT);
    draw_info(x + 28, y + 264, b"RAM erased on shutdown", SUCCESS);
    draw_info(x + 28, y + 284, b"No data persists to disk", SUCCESS);
    draw_info(x + 28, y + 304, b"Sleep/hibernate disabled", WARNING);
}

fn draw_state(x: u32, y: u32, w: u32, name: &[u8], status: &[u8], color: u32) {
    draw_string(x, y, name, TEXT_DIM);
    fill_rounded_rect(x + w - 80, y - 2, 70, 18, 3, BG_STATE);
    let sx = x + w - 78 + (66 - status.len() as u32 * 8) / 2;
    draw_string(sx, y + 1, status, color);
}

fn draw_info(x: u32, y: u32, text: &[u8], color: u32) {
    draw_string(x, y, text, color);
}

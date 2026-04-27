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
    draw_battery_card(x, y, w);
    fill_rounded_rect(x + 16, y + 90, w - 32, 80, 8, BG_CARD);
    draw_string(x + 28, y + 102, b"Power Actions", TEXT);
    draw_string(x + 28, y + 118, b"All data lost on power action", WARNING);
    fill_rounded_rect(x + 28, y + 138, 120, 24, 4, BG_DANGER);
    draw_string(x + 48, y + 143, b"Shutdown", TEXT);
    fill_rounded_rect(x + 156, y + 138, 100, 24, 4, BG_PRIMARY);
    draw_string(x + 180, y + 143, b"Reboot", TEXT);
    fill_rounded_rect(x + 16, y + 180, w - 32, 130, 8, BG_CARD);
    draw_string(x + 28, y + 192, b"Power States (ACPI)", TEXT);
    draw_state(x + 28, y + 214, w - 56, b"S0 Working", b"ACTIVE", SUCCESS);
    draw_state(x + 28, y + 236, w - 56, b"S1 Standby", b"BLOCKED", ERROR);
    draw_state(x + 28, y + 258, w - 56, b"S3 Suspend", b"BLOCKED", ERROR);
    draw_state(x + 28, y + 280, w - 56, b"S5 Soft Off", b"AVAILABLE", SUCCESS);
    fill_rounded_rect(x + 16, y + 320, w - 32, 100, 8, BG_CARD);
    draw_string(x + 28, y + 332, b"ZeroState Security", TEXT);
    draw_info(x + 28, y + 354, b"RAM erased on shutdown", SUCCESS);
    draw_info(x + 28, y + 374, b"No data persists to disk", SUCCESS);
    draw_info(x + 28, y + 394, b"Sleep/hibernate disabled", WARNING);
}

fn draw_battery_card(x: u32, y: u32, w: u32) {
    use crate::graphics::desktop::status::battery;
    fill_rounded_rect(x + 16, y, w - 32, 80, 8, BG_CARD);
    draw_string(x + 28, y + 12, b"Battery Status", TEXT);
    let pct = battery::get_battery_percent();
    let ac = battery::is_ac_connected();
    let charging = battery::is_charging();
    let (status, color) = if charging {
        (b"Charging" as &[u8], SUCCESS)
    } else if ac {
        (b"Plugged In" as &[u8], SUCCESS)
    } else {
        (b"On Battery" as &[u8], WARNING)
    };
    draw_string(x + 28, y + 32, status, color);
    let mut pct_buf = [0u8; 4];
    pct_buf[0] = b'0' + (pct / 100) % 10;
    pct_buf[1] = b'0' + (pct / 10) % 10;
    pct_buf[2] = b'0' + pct % 10;
    pct_buf[3] = b'%';
    let start = if pct >= 100 {
        0
    } else if pct >= 10 {
        1
    } else {
        2
    };
    draw_string(x + 28, y + 52, &pct_buf[start..], TEXT);
    fill_rounded_rect(x + 80, y + 50, 180, 18, 4, BG_STATE);
    let bar_w = ((pct as u32) * 176) / 100;
    let bar_c = if pct > 20 { SUCCESS } else { ERROR };
    fill_rounded_rect(x + 82, y + 52, bar_w, 14, 3, bar_c);
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

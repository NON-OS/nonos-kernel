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

use crate::display::framebuffer::{COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::graphics::framebuffer::{fill_rect};
use crate::graphics::window::settings::render::draw_string;
use crate::sys::settings as sys_settings;

pub(super) fn draw_timezone(x: u32, y: u32, w: u32) {
    draw_string(x + 28, y + 330, b"Timezone", COLOR_TEXT_WHITE);
    fill_rect(x + 28, y + 350, w - 72, 36, 0xFF1A1F26);
    fill_rect(x + 33, y + 355, 26, 26, 0xFF2D333B);
    draw_string(x + 41, y + 360, b"<", COLOR_TEXT_WHITE);
    draw_tz_name(x + 73, y + 361, sys_settings::timezone());
    fill_rect(x + w - 59, y + 355, 26, 26, 0xFF2D333B);
    draw_string(x + w - 51, y + 360, b">", COLOR_TEXT_WHITE);
}

pub(super) fn draw_screen_timeout(x: u32, y: u32, _w: u32) {
    draw_string(x + 28, y + 470, b"Screen Timeout", COLOR_TEXT_WHITE);
    let timeouts: [&[u8]; 5] = [b"Never", b"5min", b"10min", b"30min", b"60min"];
    let current = timeout_to_idx(sys_settings::screen_timeout());
    let btn_w = 55u32;
    for (i, name) in timeouts.iter().enumerate() {
        let bx = x + 28 + (i as u32) * (btn_w + 6);
        let by = y + 490;
        let is_sel = current == i;
        let color = if is_sel { COLOR_ACCENT } else { 0xFF2D333B };
        fill_rect(bx, by, btn_w, 26, color);
        let txt = if is_sel { 0xFF0D1117 } else { COLOR_TEXT_WHITE };
        draw_string(bx + 8, by + 7, name, txt);
    }
}

fn draw_tz_name(x: u32, y: u32, tz: i8) {
    let name: &[u8] = match tz {
        -12 => b"UTC-12 Baker",
        -11 => b"UTC-11 Samoa",
        -10 => b"UTC-10 Hawaii",
        -9 => b"UTC-9 Alaska",
        -8 => b"UTC-8 Pacific",
        -7 => b"UTC-7 Mountain",
        -6 => b"UTC-6 Central",
        -5 => b"UTC-5 Eastern",
        -4 => b"UTC-4 Atlantic",
        -3 => b"UTC-3 Brazil",
        -2 => b"UTC-2",
        -1 => b"UTC-1 Azores",
        0 => b"UTC+0 London",
        1 => b"UTC+1 Berlin",
        2 => b"UTC+2 Cairo",
        3 => b"UTC+3 Moscow",
        4 => b"UTC+4 Dubai",
        5 => b"UTC+5 Karachi",
        6 => b"UTC+6 Dhaka",
        7 => b"UTC+7 Bangkok",
        8 => b"UTC+8 Singapore",
        9 => b"UTC+9 Tokyo",
        10 => b"UTC+10 Sydney",
        11 => b"UTC+11",
        12 => b"UTC+12 Auckland",
        13 => b"UTC+13 Samoa",
        14 => b"UTC+14 Kiritimati",
        _ => b"UTC+0 London",
    };
    draw_string(x, y, name, COLOR_TEXT_WHITE);
}

fn timeout_to_idx(t: u8) -> usize {
    match t {
        0 => 0,
        1..=5 => 1,
        6..=10 => 2,
        11..=30 => 3,
        _ => 4,
    }
}

pub(super) fn idx_to_timeout(idx: u8) -> u8 {
    match idx {
        0 => 0,
        1 => 5,
        2 => 10,
        3 => 30,
        _ => 60,
    }
}

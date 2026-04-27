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

use crate::graphics::framebuffer::{fill_rect, put_pixel};

const COLOR_ICON: u32 = 0xFFCCCCCC;

pub(super) fn draw_gear_icon(x: u32, y: u32) {
    for dy in 0..14u32 {
        for dx in 0..14u32 {
            let rel_x = dx as i32 - 7;
            let rel_y = dy as i32 - 7;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            let angle = atan2_approx(rel_y, rel_x);
            let tooth = ((angle + 22) / 45) % 2;
            let outer = if tooth == 0 { 7u32 } else { 5 };

            if dist <= outer && dist >= 2 {
                put_pixel(x + dx, y + dy, COLOR_ICON);
            }
        }
    }
}

pub(super) fn draw_network_icon(x: u32, y: u32) {
    super::status::render::draw_network_icon(x, y);
}

pub(super) fn draw_bell_icon(x: u32, y: u32) {
    fill_rect(x + 4, y + 2, 6, 6, COLOR_ICON);
    fill_rect(x + 3, y + 6, 8, 2, COLOR_ICON);
    fill_rect(x + 2, y + 8, 10, 2, COLOR_ICON);
    fill_rect(x + 6, y, 2, 2, COLOR_ICON);
    fill_rect(x + 6, y + 11, 2, 2, COLOR_ICON);
}

pub(super) fn draw_battery(x: u32, y: u32) {
    super::status::render::draw_battery_icon(x, y);
}

pub(super) fn isqrt(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

pub(super) fn atan2_approx(y: i32, x: i32) -> i32 {
    if x == 0 && y == 0 {
        return 0;
    }
    let ax = x.abs();
    let ay = y.abs();
    let angle = if ax > ay {
        45 * ay / ax
    } else if ay > 0 {
        90 - 45 * ax / ay
    } else {
        0
    };
    match (x >= 0, y >= 0) {
        (true, true) => angle,
        (false, true) => 180 - angle,
        (false, false) => 180 + angle,
        (true, false) => 360 - angle,
    }
}

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
const COLOR_ICON_ACCENT: u32 = 0xFF00D4FF;
const COLOR_GREEN: u32 = 0xFF34D399;
const COLOR_ORANGE: u32 = 0xFFF59E0B;
const COLOR_GRAY: u32 = 0xFF6B7280;

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

/*
 * network icon shows real connection status:
 * - green: ethernet connected with IP
 * - orange: ethernet present, no IP
 * - gray: no network hardware detected
 * - wifi arcs: fallback when no ethernet (wifi not yet supported)
 */
pub(super) fn draw_network_icon(x: u32, y: u32) {
    let has_ethernet = crate::drivers::e1000::is_present();
    let has_ip = crate::network::stack::get_current_ipv4().is_some();
    let is_connected = has_ethernet && has_ip;

    let color = if is_connected {
        COLOR_GREEN
    } else if has_ethernet {
        COLOR_ORANGE
    } else {
        COLOR_GRAY
    };

    if has_ethernet {
        for i in 0..4u32 {
            let bar_h = if is_connected { 4 + i * 2 } else { 3 };
            let bar_color = if is_connected { COLOR_GREEN } else { COLOR_GRAY };
            fill_rect(x + 2 + i * 4, y + 12 - bar_h, 3, bar_h, bar_color);
        }
    } else {
        for arc in 0..3u32 {
            let r = 4 + arc * 3;
            draw_wifi_arc(x + 8, y + 12, r, COLOR_GRAY);
        }
        draw_dot(x + 7, y + 11, 1, color);
    }
}

fn draw_wifi_arc(cx: u32, cy: u32, r: u32, color: u32) {
    for angle in 0..32u32 {
        let dx = ((angle as i32 - 16) * r as i32) / 16;
        let dy_sq = (r * r) as i32 - dx * dx;
        if dy_sq > 0 {
            let dy = isqrt(dy_sq as u32);
            if dy < r && dx.abs() < r as i32 {
                let px = cx as i32 + dx;
                let py = cy as i32 - dy as i32;
                if py > 0 {
                    put_pixel(px as u32, py as u32, color);
                }
            }
        }
    }
}

pub(super) fn draw_search_icon(x: u32, y: u32) {
    for dy in 0..10u32 {
        for dx in 0..10u32 {
            let rel_x = dx as i32 - 4;
            let rel_y = dy as i32 - 4;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            if dist_sq >= 10 && dist_sq <= 18 {
                put_pixel(x + dx, y + dy, COLOR_ICON);
            }
        }
    }
    for i in 0..5u32 {
        put_pixel(x + 9 + i, y + 9 + i, COLOR_ICON);
        put_pixel(x + 10 + i, y + 9 + i, COLOR_ICON);
    }
}

pub(super) fn draw_bell_icon(x: u32, y: u32) {
    fill_rect(x + 4, y + 2, 6, 6, COLOR_ICON);
    fill_rect(x + 3, y + 6, 8, 2, COLOR_ICON);
    fill_rect(x + 2, y + 8, 10, 2, COLOR_ICON);
    fill_rect(x + 6, y, 2, 2, COLOR_ICON);
    fill_rect(x + 6, y + 11, 2, 2, COLOR_ICON);
}

pub(super) fn draw_battery(x: u32, y: u32) {
    fill_rect(x, y, 22, 11, 0xFF4B5563);
    fill_rect(x + 1, y + 1, 20, 9, 0xFF1F2937);
    fill_rect(x + 22, y + 3, 2, 5, 0xFF4B5563);
    fill_rect(x + 2, y + 2, 18, 7, COLOR_GREEN);
    fill_rect(x + 9, y + 2, 4, 2, 0xFF065F46);
    fill_rect(x + 8, y + 4, 4, 2, 0xFF065F46);
    fill_rect(x + 10, y + 6, 4, 2, 0xFF065F46);
}

pub(super) fn draw_avatar(x: u32, y: u32) {
    let size = 20u32;
    let radius = size / 2;

    for dy in 0..size {
        for dx in 0..size {
            let rel_x = dx as i32 - radius as i32;
            let rel_y = dy as i32 - radius as i32;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            if dist_sq <= radius * radius {
                put_pixel(x + dx, y + dy, COLOR_ICON_ACCENT);
            }
        }
    }

    crate::graphics::font::draw_char(x + 6, y + 5, b'U', 0xFF0A0E14);
    draw_dot(x + size - 4, y + size - 4, 2, COLOR_GREEN);
}

pub(super) fn draw_dot(cx: u32, cy: u32, r: u32, color: u32) {
    for dy in 0..r * 2 + 1 {
        for dx in 0..r * 2 + 1 {
            let rel_x = dx as i32 - r as i32;
            let rel_y = dy as i32 - r as i32;
            if rel_x * rel_x + rel_y * rel_y <= (r * r) as i32 {
                put_pixel(cx - r + dx, cy - r + dy, color);
            }
        }
    }
}

pub(super) fn isqrt(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

pub(super) fn atan2_approx(y: i32, x: i32) -> i32 {
    if x == 0 && y == 0 { return 0; }
    let ax = x.abs();
    let ay = y.abs();
    let angle = if ax > ay { 45 * ay / ax } else if ay > 0 { 90 - 45 * ax / ay } else { 0 };
    match (x >= 0, y >= 0) {
        (true, true) => angle,
        (false, true) => 180 - angle,
        (false, false) => 180 + angle,
        (true, false) => 360 - angle,
    }
}

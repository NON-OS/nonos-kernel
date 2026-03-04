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

const COLOR_CYAN_SOFT: u32 = 0xFF6EEEFF;
const COLOR_GREEN: u32 = 0xFF00E676;
const COLOR_CYAN: u32 = 0xFF00D4FF;
pub(super) const GLASS_BG: u32 = 0xE8101418;

pub(super) fn draw_divider(x: u32, y: u32, h: u32) {
    for dy in 0..h {
        let t = (dy * 256) / h;
        let alpha = if t < 64 {
            t / 4
        } else if t > 192 {
            (256 - t) / 4
        } else {
            16
        };
        put_pixel(x, y + dy, (alpha << 24) | 0xFFFFFF);
    }
}

pub(super) fn draw_gear_icon(x: u32, y: u32) {
    let cx = x + 7;
    let cy = y + 7;
    let center_dist = cx.saturating_sub(cy).min(1);

    for dy in (0 + center_dist)..14u32 {
        for dx in 0..14u32 {
            let rel_x = dx as i32 - 7;
            let rel_y = dy as i32 - 7;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            let angle = atan2_approx(rel_y, rel_x);
            let tooth = ((angle + 22) / 45) % 2;
            let outer = if tooth == 0 { 7u32 } else { 5 };

            if dist <= outer && dist >= 2 {
                put_pixel(x + dx, y + dy, COLOR_CYAN_SOFT);
            }
        }
    }
}

pub(super) fn draw_network_icon(x: u32, y: u32) {
    let has_ethernet = crate::drivers::e1000::is_present();
    let has_ip = crate::network::stack::get_current_ipv4().is_some();
    let is_connected = has_ethernet && has_ip;

    let color = if is_connected {
        COLOR_GREEN
    } else if has_ethernet {
        0xFFFFAA00
    } else {
        0xFF666666
    };

    if has_ethernet {
        fill_rect(x + 4, y + 2, 8, 8, color);
        fill_rect(x + 5, y + 3, 6, 6, GLASS_BG);

        for i in 0..3u32 {
            fill_rect(x + 6 + i * 2, y + 4, 1, 4, color);
        }

        fill_rect(x + 6, y + 10, 4, 2, color);

        if is_connected {
            draw_dot(x + 11, y + 2, 2, COLOR_GREEN);
        }
    } else {
        for arc in 0..3u32 {
            let arc_color = 0xFF666666;
            let r = 4 + arc * 3;
            draw_wifi_arc(x + 8, y + 12, r, arc_color);
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
            if dist_sq >= 12 && dist_sq <= 20 {
                put_pixel(x + dx, y + dy, COLOR_CYAN_SOFT);
            }
        }
    }

    for i in 0..4u32 {
        put_pixel(x + 9 + i, y + 9 + i, COLOR_CYAN_SOFT);
        put_pixel(x + 10 + i, y + 9 + i, COLOR_CYAN_SOFT);
    }
}

pub(super) fn draw_bell_icon(x: u32, y: u32) {
    fill_rect(x + 4, y + 2, 6, 7, COLOR_CYAN_SOFT);
    fill_rect(x + 3, y + 6, 8, 3, COLOR_CYAN_SOFT);
    fill_rect(x + 2, y + 8, 10, 2, COLOR_CYAN_SOFT);

    fill_rect(x + 5, y, 4, 2, COLOR_CYAN_SOFT);
    fill_rect(x + 6, y, 2, 1, COLOR_CYAN_SOFT);

    fill_rect(x + 6, y + 11, 2, 2, COLOR_CYAN_SOFT);
}

pub(super) fn draw_battery(x: u32, y: u32) {
    fill_rect(x, y, 24, 12, 0xFF3D4450);
    fill_rect(x + 1, y + 1, 22, 10, GLASS_BG);

    fill_rect(x + 24, y + 3, 2, 6, 0xFF3D4450);

    let level = 17u32;
    fill_rect(x + 2, y + 2, level, 8, COLOR_GREEN);

    fill_rect(x + 2, y + 2, level, 1, 0x20FFFFFF);
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
                let shade = (dy * 30 / size) as u32;
                let r = 0x00 + shade;
                let g = 0xC4 - shade * 2;
                let b = 0xFF - shade;
                put_pixel(x + dx, y + dy, 0xFF000000 | (r << 16) | (g << 8) | b);
            }

            if dist_sq >= (radius - 2) * (radius - 2) && dist_sq <= radius * radius {
                put_pixel(x + dx, y + dy, COLOR_CYAN);
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

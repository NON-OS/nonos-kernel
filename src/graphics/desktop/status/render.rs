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

use super::{battery, network};
use crate::graphics::design_system::colors;
use crate::graphics::framebuffer::{fill_rect, put_pixel};

const COLOR_SUCCESS: u32 = colors::SUCCESS;
const COLOR_WARNING: u32 = colors::WARNING;
const COLOR_ERROR: u32 = colors::ERROR;

pub fn draw_battery_icon(x: u32, y: u32) {
    let percent = battery::get_battery_percent();
    let state = battery::get_battery_state();
    let fill_color = match percent {
        0..=20 => COLOR_ERROR,
        21..=40 => COLOR_WARNING,
        _ => COLOR_SUCCESS,
    };
    fill_rect(x, y, 22, 11, 0xFF4B5563);
    fill_rect(x + 1, y + 1, 20, 9, 0xFF1F2937);
    fill_rect(x + 22, y + 3, 2, 5, 0xFF4B5563);
    let fill_w = (percent as u32 * 18) / 100;
    if fill_w > 0 {
        fill_rect(x + 2, y + 2, fill_w, 7, fill_color);
    }
    if state == battery::BatteryState::Charging {
        draw_lightning(x + 8, y + 2);
    }
}

fn draw_lightning(x: u32, y: u32) {
    put_pixel(x + 2, y, 0xFFFFFFFF);
    put_pixel(x + 1, y + 1, 0xFFFFFFFF);
    put_pixel(x + 2, y + 1, 0xFFFFFFFF);
    put_pixel(x, y + 2, 0xFFFFFFFF);
    put_pixel(x + 1, y + 2, 0xFFFFFFFF);
    put_pixel(x + 2, y + 3, 0xFFFFFFFF);
    put_pixel(x + 3, y + 4, 0xFFFFFFFF);
}

pub fn draw_network_icon(x: u32, y: u32) {
    let state = network::get_network_state();
    let net_type = network::get_network_type();
    let color = match state {
        network::NetworkState::Connected => COLOR_SUCCESS,
        network::NetworkState::NoInternet => COLOR_WARNING,
        _ => 0xFF6B7280,
    };
    match net_type {
        network::NetworkType::Ethernet => {
            draw_ethernet_bars(x, y, color, state == network::NetworkState::Connected)
        }
        network::NetworkType::Wifi => draw_wifi_arcs(x, y, color, network::get_wifi_signal()),
        network::NetworkType::None => draw_wifi_arcs(x, y, 0xFF6B7280, 0),
    }
}

fn draw_ethernet_bars(x: u32, y: u32, color: u32, connected: bool) {
    for i in 0..4u32 {
        let bar_h = if connected { 4 + i * 2 } else { 3 };
        let bar_color = if connected { color } else { 0xFF6B7280 };
        fill_rect(x + 2 + i * 4, y + 12 - bar_h, 3, bar_h, bar_color);
    }
}

fn draw_wifi_arcs(x: u32, y: u32, color: u32, bars: u8) {
    let cx = x + 8;
    let cy = y + 12;
    for arc in 0..3u32 {
        let arc_color = if (arc as u8) < bars { color } else { 0xFF3B3B3B };
        let r = 4 + arc * 3;
        draw_arc(cx, cy, r, arc_color);
    }
    let dot_color = if bars > 0 { color } else { 0xFF3B3B3B };
    fill_rect(cx - 1, cy - 1, 3, 3, dot_color);
}

fn draw_arc(cx: u32, cy: u32, r: u32, color: u32) {
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

fn isqrt(n: u32) -> u32 {
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

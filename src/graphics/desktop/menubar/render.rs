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

use super::super::status::render::{draw_battery_icon, draw_network_icon};
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::sys::clock;

const BAR_HEIGHT: u32 = 34;
const BG: u32 = 0xF0101018;
const TEXT: u32 = 0xFFE5E5E5;
const ACCENT: u32 = 0xFF66FFFF;

pub fn draw(w: u32) {
    fill_rect(0, 0, w, BAR_HEIGHT, BG);
    fill_rect(0, BAR_HEIGHT - 1, w, 1, 0x10FFFFFF);
    draw_left_section();
    draw_center_brand(w);
    draw_right_section(w);
}

fn draw_left_section() {
    draw_logo_icon(8, 5);
    draw_text(36, 10, b"System settings", TEXT);
    fill_rect(156, 8, 1, 18, 0x30FFFFFF);
    let mut date_buf = [0u8; 12];
    let date_len = clock::format_date_only(&mut date_buf);
    draw_text(168, 10, &date_buf[..date_len], TEXT);
    let date_w = date_len as u32 * 8;
    let mut time_buf = [0u8; 8];
    clock::format_time_full(&mut time_buf);
    draw_text(168 + date_w + 8, 10, &time_buf, TEXT);
}

fn draw_logo_icon(x: u32, y: u32) {
    // Rounded square background (24x24 with radius 5)
    let size = 24u32;
    let rad = 5u32;
    for dy in 0..size {
        for dx in 0..size {
            // Check corners with rounded edges
            let in_rect = dx >= rad && dx < size - rad || dy >= rad && dy < size - rad;
            let in_corner = {
                let cx = if dx < rad { rad } else { size - rad - 1 };
                let cy = if dy < rad { rad } else { size - rad - 1 };
                let rdx = if dx < rad { rad - dx } else if dx >= size - rad { dx - (size - rad - 1) } else { 0 };
                let rdy = if dy < rad { rad - dy } else if dy >= size - rad { dy - (size - rad - 1) } else { 0 };
                rdx * rdx + rdy * rdy <= rad * rad
            };
            if in_rect || in_corner {
                put_pixel(x + dx, y + dy, ACCENT);
            }
        }
    }
    // Draw Ø symbol centered (dark on cyan)
    let cx = x + 12;
    let cy = y + 12;
    let dark = 0xFF101018u32;
    // Circle using midpoint algorithm
    let r = 6i32;
    for dy in -r..=r {
        for ddx in -r..=r {
            let dist = ddx * ddx + dy * dy;
            if dist >= (r - 1) * (r - 1) && dist <= r * r {
                put_pixel((cx as i32 + ddx) as u32, (cy as i32 + dy) as u32, dark);
            }
        }
    }
    // Diagonal slash through the O
    for i in 0..10u32 {
        put_pixel(cx - 4 + i, cy + 4 - i, dark);
    }
}

fn draw_center_brand(w: u32) {
    let text = b"N\xd8NOS";
    let text_w = text.len() as u32 * 8;
    draw_text(w / 2 - text_w / 2, 10, text, TEXT);
}

fn draw_right_section(w: u32) {
    let mut x = w - 24;
    draw_signal_bars(x, 9);
    x -= 28;
    draw_battery_icon(x, 10);
    x -= 28;
    draw_search_icon(x, 9);
    x -= 24;
    draw_network_icon(x, 8);
}

fn draw_signal_bars(x: u32, y: u32) {
    for i in 0..4u32 {
        let h = 4 + i * 3;
        fill_rect(x + i * 4, y + 12 - h, 3, h, TEXT);
    }
}

fn draw_search_icon(x: u32, y: u32) {
    for r in 4..6u32 {
        for a in 0..32u32 {
            let dx = ((a as i32 - 16) * r as i32) / 16;
            let dy_sq = (r * r) as i32 - dx * dx;
            if dy_sq > 0 {
                let dy = isqrt(dy_sq as u32);
                put_pixel((x as i32 + 6 + dx) as u32, (y as i32 + 6 - dy as i32) as u32, TEXT);
                put_pixel((x as i32 + 6 + dx) as u32, (y as i32 + 6 + dy as i32) as u32, TEXT);
            }
        }
    }
    fill_rect(x + 10, y + 10, 4, 2, TEXT);
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

pub fn handle_click(mx: i32, my: i32, _w: u32) -> bool {
    if my < 0 || my >= BAR_HEIGHT as i32 {
        return false;
    }
    if mx >= 8 && mx < 140 {
        crate::graphics::window::open(crate::graphics::window::WindowType::Settings);
        return true;
    }
    true
}

pub fn update_clock() {
    crate::graphics::desktop::status::battery::update_battery_status();
    crate::graphics::desktop::status::network::update_network_status();
}

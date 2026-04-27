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

use super::render::*;
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::draw_string;

pub(super) fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r {
        for dx in 0..r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(x + r - dx, y + r - dy, color);
                put_pixel(x + w - r + dx - 1, y + r - dy, color);
                put_pixel(x + r - dx, y + h - r + dy - 1, color);
                put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
            }
        }
    }
}

pub(super) fn draw_section_header(x: u32, y: u32, text: &[u8]) {
    draw_string(x, y, text, COLOR_TEXT_WHITE);
    fill_rect(x, y + 20, 60, 2, COLOR_ACCENT);
    for i in 0..3 {
        fill_rect(x + 60 + i * 2, y + 20, 1, 2, blend_alpha(COLOR_ACCENT, 60 - i * 20));
    }
}

pub(super) fn draw_premium_button(
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    text: &[u8],
    color: u32,
    glow: u32,
) {
    for i in 0..4 {
        draw_rounded_rect(x + i / 2, y + 3 + i, w, h, 10, blend_alpha(0x000000, 20 - i * 4));
    }
    draw_rounded_rect(x, y, w, h, 10, color);
    draw_button_highlight(x, y, w, h, 10, glow);
    let text_x = x + (w - text.len() as u32 * 8) / 2;
    draw_string(text_x, y + (h - 12) / 2, text, 0xFF000000);
}

fn draw_button_highlight(x: u32, y: u32, w: u32, _h: u32, r: u32, glow: u32) {
    for row in 0..core::cmp::min(r, 8) {
        let alpha = 40 - row * 5;
        let in_radius = row < r;
        let start_x = if in_radius { x + r - isqrt(r * r - (r - row) * (r - row)) } else { x };
        let end_x =
            if in_radius { x + w - r + isqrt(r * r - (r - row) * (r - row)) } else { x + w };
        if end_x > start_x {
            fill_rect(start_x, y + row, end_x - start_x, 1, blend_alpha(glow, alpha));
        }
    }
}

pub(super) fn blend_alpha(color: u32, alpha: u32) -> u32 {
    let a = (alpha * 255 / 100).min(255);
    (a << 24) | (color & 0x00FFFFFF)
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

pub(super) fn account_color(index: u32) -> u32 {
    let colors = [COLOR_ACCENT, COLOR_PURPLE, COLOR_GREEN, COLOR_YELLOW, COLOR_CYAN, COLOR_RED];
    colors[(index as usize) % colors.len()]
}

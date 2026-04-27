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

use super::constants::*;
use super::primitives::{draw_circle_aa, draw_corner, isqrt};
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::state::TITLE_BAR_HEIGHT;

pub(super) fn draw_titlebar(x: u32, y: u32, w: u32, focused: bool, title: &[u8], maximized: bool) {
    let tb_bg = if focused { TITLEBAR_FOCUSED } else { TITLEBAR_UNFOCUSED };
    fill_rect(x + CORNER_RADIUS, y, w.saturating_sub(CORNER_RADIUS * 2), TITLE_BAR_HEIGHT, tb_bg);
    fill_rect(x, y + CORNER_RADIUS, CORNER_RADIUS, TITLE_BAR_HEIGHT - CORNER_RADIUS, tb_bg);
    fill_rect(
        x + w - CORNER_RADIUS,
        y + CORNER_RADIUS,
        CORNER_RADIUS,
        TITLE_BAR_HEIGHT - CORNER_RADIUS,
        tb_bg,
    );
    draw_corner(x + CORNER_RADIUS, y + CORNER_RADIUS, CORNER_RADIUS, tb_bg, 0);
    draw_corner(x + w - CORNER_RADIUS - 1, y + CORNER_RADIUS, CORNER_RADIUS, tb_bg, 1);
    if focused {
        fill_rect(x + CORNER_RADIUS, y, w.saturating_sub(CORNER_RADIUS * 2), 1, 0x0AFFFFFF);
    }
    fill_rect(x, y + TITLE_BAR_HEIGHT - 1, w, 1, 0x18000000);
    let btn_y = y + TITLE_BAR_HEIGHT / 2;
    draw_traffic_light(x + 18, btn_y, BTN_CLOSE, focused);
    draw_traffic_light(x + 38, btn_y, BTN_MIN, focused);
    draw_traffic_light(x + 58, btn_y, BTN_MAX, focused);
    if maximized {
        for dy in 0..3u32 {
            for dx in 0..3u32 {
                put_pixel(x + 56 + dx, btn_y - 1 + dy, 0xFF0D5F1A);
            }
        }
    }
    let title_len = title.len() as u32;
    let title_x = x + (w / 2).saturating_sub(title_len * 4);
    let title_color = if focused { 0xFFF0F0F4 } else { 0xFF68686E };
    for (i, &ch) in title.iter().enumerate() {
        draw_char(title_x + (i as u32) * 8, y + 8, ch, title_color);
    }
}

fn draw_traffic_light(cx: u32, cy: u32, color: u32, focused: bool) {
    let r = 6u32;
    let display_color = if focused { color } else { 0xFF4A4A52 };
    draw_circle_aa(cx, cy, r, display_color);
    if focused {
        for dy in 0..r / 2 {
            let row_width = isqrt(r * r - (r - dy) * (r - dy));
            let alpha = 35u32.saturating_sub(dy * 10);
            if alpha > 0 {
                for dx in 0..row_width {
                    put_pixel(cx - row_width / 2 + dx, cy - r / 2 + dy, (alpha << 24) | 0xFFFFFF);
                }
            }
        }
    }
}

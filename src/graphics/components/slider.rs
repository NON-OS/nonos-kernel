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

use super::primitives::circle;
use crate::graphics::design_system::colors;
use crate::graphics::framebuffer::rounded_rect_blend;

pub const SLIDER_HEIGHT: u32 = 24;
pub const TRACK_HEIGHT: u32 = 4;
pub const THUMB_RADIUS: u32 = 8;

pub fn draw_slider(x: u32, y: u32, w: u32, value: f32, dragging: bool) {
    let clamped = value.clamp(0.0, 1.0);
    let track_y = y + (SLIDER_HEIGHT - TRACK_HEIGHT) / 2;
    rounded_rect_blend(x, track_y, w, TRACK_HEIGHT, 2, colors::GLASS_BG_DARK);
    let fill_w = ((w as f32 - THUMB_RADIUS as f32 * 2.0) * clamped) as u32;
    if fill_w > 0 {
        rounded_rect_blend(x, track_y, fill_w + THUMB_RADIUS, TRACK_HEIGHT, 2, colors::ACCENT);
    }
    let thumb_x = x + THUMB_RADIUS + fill_w;
    let thumb_y = y + SLIDER_HEIGHT / 2;
    draw_thumb(thumb_x, thumb_y, dragging);
}

fn draw_thumb(cx: u32, cy: u32, dragging: bool) {
    if dragging {
        circle(cx, cy, THUMB_RADIUS + 4, colors::GLASS_GLOW_ACCENT);
    }
    circle(cx, cy, THUMB_RADIUS, colors::BG_ELEVATED);
    circle(cx, cy, THUMB_RADIUS - 2, colors::ACCENT);
}

pub fn slider_hit_test(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    let track_y = y as i32;
    click_x >= x as i32
        && click_x < (x + w) as i32
        && click_y >= track_y
        && click_y < track_y + SLIDER_HEIGHT as i32
}

pub fn slider_value_from_x(x: u32, w: u32, click_x: i32) -> f32 {
    let rel_x = click_x - x as i32 - THUMB_RADIUS as i32;
    let track_w = w as i32 - THUMB_RADIUS as i32 * 2;
    if track_w <= 0 {
        return 0.0;
    }
    (rel_x as f32 / track_w as f32).clamp(0.0, 1.0)
}

pub fn draw_slider_with_label(x: u32, y: u32, w: u32, value: f32, label: &[u8], dragging: bool) {
    use crate::graphics::font::draw_text;
    draw_text(x, y, label, colors::TEXT_PRIMARY);
    let val_str = format_percent(value);
    let val_x = x + w - val_str.len() as u32 * 8;
    draw_text(val_x, y, &val_str, colors::TEXT_SECONDARY);
    draw_slider(x, y + 20, w, value, dragging);
}

fn format_percent(v: f32) -> [u8; 4] {
    let pct = (v * 100.0) as u32;
    let d0 = b'0' + (pct / 100) as u8;
    let d1 = b'0' + ((pct / 10) % 10) as u8;
    let d2 = b'0' + (pct % 10) as u8;
    if pct >= 100 {
        [d0, d1, d2, b'%']
    } else if pct >= 10 {
        [b' ', d1, d2, b'%']
    } else {
        [b' ', b' ', d2, b'%']
    }
}

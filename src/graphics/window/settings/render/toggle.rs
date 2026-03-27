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

pub fn draw_toggle(x: u32, y: u32, enabled: bool) {
    let track_color = if enabled { 0xFF34D399 } else { 0xFF374151 };
    let h = 28u32;
    let w = 48u32;
    let r = h / 2;
    fill_rect(x + r, y, w - h, h, track_color);
    draw_toggle_cap(x, y, r, track_color, true);
    draw_toggle_cap(x + w - h, y, r, track_color, false);
    let knob_x = if enabled { x + w - h + 2 } else { x + 2 };
    let knob_r = (h - 4) / 2;
    draw_toggle_knob(knob_x + knob_r, y + h / 2, knob_r);
}

fn draw_toggle_cap(x: u32, y: u32, r: u32, color: u32, left: bool) {
    let r_sq = (r * r) as i32;
    for dy in 0..=r {
        for dx in 0..=r {
            if (dx * dx + dy * dy) as i32 <= r_sq {
                let px = if left { x + r - dx } else { x + dx };
                put_pixel(px, y + r - dy, color);
                put_pixel(px, y + r + dy, color);
            }
        }
    }
}

fn draw_toggle_knob(cx: u32, cy: u32, r: u32) {
    let r_sq = (r * r) as i32;
    for dy in 0..=r {
        for dx in 0..=r {
            let dist = (dx * dx + dy * dy) as i32;
            if dist <= r_sq {
                let shade = 255 - (dy * 15 / r) as u32;
                let color = (0xFF << 24) | (shade << 16) | (shade << 8) | shade;
                put_pixel(cx + dx, cy + dy, color);
                put_pixel(cx + dx, cy - dy, color);
                put_pixel(cx - dx, cy + dy, color);
                put_pixel(cx - dx, cy - dy, color);
            }
        }
    }
}

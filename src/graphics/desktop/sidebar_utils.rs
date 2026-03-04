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
use super::sidebar_icons::draw_icon_plate;

const COLOR_CYAN: u32 = 0xFF00D4FF;

#[allow(dead_code)]
pub(super) fn draw_settings_icon(cx: u32, cy: u32) {
    draw_icon_plate(cx, cy, 40);

    let center_x = cx;
    let center_y = cy;

    let outer_r = 14u32;
    let inner_r = 10u32;
    let hole_r = 5u32;
    let teeth = 8u32;

    for dy in 0..outer_r * 2 + 4 {
        for dx in 0..outer_r * 2 + 4 {
            let px = center_x as i32 - outer_r as i32 - 2 + dx as i32;
            let py = center_y as i32 - outer_r as i32 - 2 + dy as i32;

            let rel_x = dx as i32 - outer_r as i32 - 2;
            let rel_y = dy as i32 - outer_r as i32 - 2;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            let angle = atan2_approx(rel_y, rel_x);
            let tooth_wave = ((angle * teeth as i32 / 360 + 1000) % 2) as u32;

            let effective_outer = if tooth_wave == 0 { outer_r } else { outer_r - 3 };

            if dist <= effective_outer && dist >= hole_r {
                let shade = if dist < inner_r {
                    blend_colors(COLOR_CYAN, 0xFF008899, 128)
                } else {
                    COLOR_CYAN
                };

                let final_color = if rel_y < -2 {
                    blend_colors(shade, 0xFFFFFFFF, 30)
                } else if rel_y > 2 {
                    blend_colors(shade, 0xFF000000, 30)
                } else {
                    shade
                };

                put_pixel(px as u32, py as u32, final_color);
            }
        }
    }

    for dy in 0..hole_r * 2 {
        for dx in 0..hole_r * 2 {
            let rel_x = dx as i32 - hole_r as i32;
            let rel_y = dy as i32 - hole_r as i32;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            if dist_sq >= (hole_r - 2) * (hole_r - 2) && dist_sq <= hole_r * hole_r {
                let px = center_x - hole_r + dx;
                let py = center_y - hole_r + dy;
                put_pixel(px, py, 0x40FFFFFF);
            }
        }
    }
}

pub(super) fn draw_info_icon(cx: u32, cy: u32) {
    let radius = 14u32;

    for dy in 0..radius * 2 + 8 {
        for dx in 0..radius * 2 + 8 {
            let rel_x = dx as i32 - radius as i32 - 4;
            let rel_y = dy as i32 - radius as i32 - 4;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            if dist > radius && dist <= radius + 4 {
                let alpha = ((radius + 4 - dist) * 15 / 4) as u32;
                let px = cx as i32 + rel_x;
                let py = cy as i32 + rel_y;
                if px > 0 && py > 0 {
                    put_pixel(px as u32, py as u32, (alpha << 24) | 0x00D4FF);
                }
            }
        }
    }

    for dy in 0..radius * 2 + 2 {
        for dx in 0..radius * 2 + 2 {
            let rel_x = dx as i32 - radius as i32 - 1;
            let rel_y = dy as i32 - radius as i32 - 1;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;

            if dist_sq <= radius * radius {
                let px = cx as i32 + rel_x;
                let py = cy as i32 + rel_y;

                let shade = ((rel_y + radius as i32) * 40 / (radius as i32 * 2)) as u8;
                let color = blend_colors(COLOR_CYAN, 0xFF008899, shade);

                put_pixel(px as u32, py as u32, color);
            }
        }
    }

    draw_circle_filled(cx, cy - 6, 2, 0xFF0A1218);
    fill_rect(cx - 2, cy - 2, 4, 10, 0xFF0A1218);
}

pub(super) fn draw_circle_filled(cx: u32, cy: u32, radius: u32, color: u32) {
    for dy in 0..radius * 2 + 1 {
        for dx in 0..radius * 2 + 1 {
            let rel_x = dx as i32 - radius as i32;
            let rel_y = dy as i32 - radius as i32;
            if rel_x * rel_x + rel_y * rel_y <= (radius * radius) as i32 {
                put_pixel(cx - radius + dx, cy - radius + dy, color);
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

    let angle = if ax > ay {
        45 * ay / ax
    } else if ay > 0 {
        90 - 45 * ax / ay
    } else {
        0
    };

    if x >= 0 && y >= 0 {
        angle
    } else if x < 0 && y >= 0 {
        180 - angle
    } else if x < 0 && y < 0 {
        180 + angle
    } else {
        360 - angle
    }
}

pub(super) fn blend_colors(color1: u32, color2: u32, factor: u8) -> u32 {
    let f = factor as u32;
    let inv_f = 255 - f;

    let r1 = (color1 >> 16) & 0xFF;
    let g1 = (color1 >> 8) & 0xFF;
    let b1 = color1 & 0xFF;

    let r2 = (color2 >> 16) & 0xFF;
    let g2 = (color2 >> 8) & 0xFF;
    let b2 = color2 & 0xFF;

    let r = (r1 * inv_f + r2 * f) / 255;
    let g = (g1 * inv_f + g2 * f) / 255;
    let b = (b1 * inv_f + b2 * f) / 255;

    0xFF000000 | (r << 16) | (g << 8) | b
}

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

use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE};
use super::render::draw_string;

const COLOR_BRAND_PRIMARY: u32 = 0xFF66FFFF;
const COLOR_BRAND_SECONDARY: u32 = 0xFF2E5C5C;
const COLOR_BG_DARK: u32 = 0xFF0A0E12;
const COLOR_TEXT_DIM: u32 = 0xFF6B8080;
const COLOR_TEXT_FEATURE: u32 = 0xFFB0D0D0;

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    let cx = x + w / 2;
    let logo_y = y + 20;
    let logo_size = 60u32;

    draw_nonos_logo(cx, logo_y, logo_size);

    let text_y = logo_y + logo_size + 12;
    let brand_text = b"N\xd8NOS";
    let brand_x = cx - (brand_text.len() as u32 * 8) / 2;
    draw_string(brand_x, text_y, brand_text, COLOR_BRAND_PRIMARY);

    let tagline = b"Trustless Operating System";
    let tagline_x = cx - (tagline.len() as u32 * 8) / 2;
    draw_string(tagline_x, text_y + 16, tagline, COLOR_TEXT_WHITE);

    let version_y = text_y + 40;
    fill_rect(cx - 50, version_y, 100, 18, COLOR_BRAND_SECONDARY);
    draw_string(cx - 40, version_y + 3, b"Version 1.0", COLOR_TEXT_WHITE);

    let div_y = version_y + 28;
    for dx in 0..(w - 60) {
        let dist_from_center = ((dx as i32) - ((w - 60) as i32 / 2)).abs() as u32;
        let max_dist = (w - 60) / 2;
        let alpha = 255 - (dist_from_center * 255 / max_dist).min(255);
        let r = ((COLOR_BRAND_PRIMARY >> 16) & 0xFF) * alpha / 255;
        let g = ((COLOR_BRAND_PRIMARY >> 8) & 0xFF) * alpha / 255;
        let b = (COLOR_BRAND_PRIMARY & 0xFF) * alpha / 255;
        put_pixel(x + 30 + dx, div_y, 0xFF000000 | (r << 16) | (g << 8) | b);
    }

    let features: [&[u8]; 4] = [
        b"Privacy First - Zero tracking, zero telemetry",
        b"RAM Only - No persistence, clean slate on reboot",
        b"Anonymous by Default - Tor network integration",
        b"Post-Quantum Ready - Future-proof cryptography",
    ];

    let feat_y = div_y + 16;
    for (i, feat) in features.iter().enumerate() {
        let fy = feat_y + (i as u32) * 22;
        draw_bullet(x + 25, fy + 4, COLOR_BRAND_PRIMARY);
        draw_string(x + 38, fy, feat, COLOR_TEXT_FEATURE);
    }

    let footer_y = y + h - 35;
    fill_rect(x + 25, footer_y - 8, w - 50, 1, COLOR_BRAND_SECONDARY);
    draw_string(x + 25, footer_y + 5, b"(C) 2026 N\xd8NOS Project", COLOR_TEXT_DIM);
    draw_string(x + w - 135, footer_y + 5, b"nonos.systems", COLOR_BRAND_PRIMARY);
}

fn draw_nonos_logo(cx: u32, y: u32, size: u32) {
    let glass_cx = cx - 8;
    let glass_cy = y + size / 2 - 8;
    let outer_r = size / 2 - 6;
    let inner_r = outer_r - 7;

    for dy in 0..size {
        for dx in 0..size {
            let rel_x = dx as i32 - (size / 2) as i32 + 8;
            let rel_y = dy as i32 - (size / 2) as i32 + 8;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            if dist > outer_r && dist <= outer_r + 5 {
                let alpha = ((outer_r + 5 - dist) * 35 / 5) as u32;
                put_pixel(cx - size / 2 + dx, y + dy, (alpha << 24) | 0x66FFFF);
            }
        }
    }

    for dy in 0..size {
        for dx in 0..size {
            let rel_x = dx as i32 - (size / 2) as i32 + 8;
            let rel_y = dy as i32 - (size / 2) as i32 + 8;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            if dist >= inner_r && dist <= outer_r {
                let t = (dy * 256 / size) as u32;
                let r = 0x66 + ((0x99 - 0x66) * (256 - t) / 512).min(0x33);
                let g = 0xFF - (t / 5).min(0x35);
                let b = 0xFF - (t / 6).min(0x25);
                put_pixel(cx - size / 2 + dx, y + dy, 0xFF000000 | (r << 16) | (g << 8) | b);
            } else if dist < inner_r && dist > inner_r / 3 {
                let shade = ((inner_r - dist) * 12 / inner_r) as u32;
                if shade > 3 {
                    put_pixel(cx - size / 2 + dx, y + dy, (shade << 24) | 0x66FFFF);
                }
            }
        }
    }

    let handle_start_x = glass_cx + (outer_r as i32 * 70 / 100) as u32;
    let handle_start_y = glass_cy + (outer_r as i32 * 70 / 100) as u32;
    let handle_len = size * 40 / 100;
    let handle_width = 9u32;

    for i in 0..handle_len {
        let hx = handle_start_x + i;
        let hy = handle_start_y + i;

        for t in 0..handle_width {
            let offset = t as i32 - (handle_width as i32 / 2);
            let px = (hx as i32 + offset / 2) as u32;
            let py = (hy as i32 - offset / 2) as u32;

            let shade = (i * 50 / handle_len) as u32;
            let r = (0x66 - shade.min(0x25)) as u32;
            let g = (0xFF - shade.min(0x50)) as u32;
            let b = (0xFF - shade.min(0x40)) as u32;

            put_pixel(px, py, 0xFF000000 | (r << 16) | (g << 8) | b);
        }
    }

    let cap_cx = handle_start_x + handle_len;
    let cap_cy = handle_start_y + handle_len;
    let cap_r = handle_width / 2;
    for dy in 0..cap_r * 2 + 2 {
        for dx in 0..cap_r * 2 + 2 {
            let rel_x = dx as i32 - cap_r as i32 - 1;
            let rel_y = dy as i32 - cap_r as i32 - 1;
            if rel_x * rel_x + rel_y * rel_y <= (cap_r * cap_r) as i32 {
                put_pixel(cap_cx - cap_r + dx, cap_cy - cap_r + dy, COLOR_BRAND_SECONDARY);
            }
        }
    }
}

fn draw_bullet(x: u32, y: u32, color: u32) {
    for dy in 0..6u32 {
        for dx in 0..6u32 {
            let rel_x = dx as i32 - 2;
            let rel_y = dy as i32 - 2;
            if rel_x * rel_x + rel_y * rel_y <= 5 {
                put_pixel(x + dx, y + dy, color);
            }
        }
    }
}

fn isqrt(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

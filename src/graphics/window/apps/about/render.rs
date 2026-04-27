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

use super::logo::draw_nonos_logo;
use super::utils::{draw_bullet, draw_rounded_pill};
use crate::graphics::components::text;
use crate::graphics::design_system::colors::{ACCENT, SUCCESS, TEXT_PRIMARY, TEXT_SECONDARY};
use crate::graphics::framebuffer::{fill_rect, put_pixel};

const COLOR_BRAND_GLOW: u32 = 0xFF22D3EE;
const COLOR_BRAND_SECONDARY: u32 = 0xFF2A2A32;
const COLOR_BRAND_PRIMARY: u32 = 0xFF3B82F6;
const COLOR_PURPLE: u32 = 0xFFA78BFA;
const COLOR_ORANGE: u32 = 0xFFF59E0B;

pub(crate) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, 0xFF141418);
    let cx = x + w / 2;
    let logo_y = y + 24;
    draw_nonos_logo(cx, logo_y, 64);

    let text_y = logo_y + 80;
    text::draw_centered(x, text_y, w, b"N\xd8NOS", COLOR_BRAND_GLOW);
    text::draw_centered(x, text_y + 18, w, b"Trustless Operating System", TEXT_PRIMARY);

    let version_y = text_y + 46;
    draw_rounded_pill(cx - 55, version_y, 110, 24, COLOR_BRAND_SECONDARY);
    text::draw(cx - 44, version_y + 6, b"Version 1.0", TEXT_PRIMARY);

    draw_divider(x, version_y + 36, w);
    draw_features(x, version_y + 56, w);
    draw_footer(x, y + h - 40, w);
}

fn draw_divider(x: u32, y: u32, w: u32) {
    for dx in 0..(w - 60) {
        let dist = ((dx as i32) - ((w - 60) as i32 / 2)).abs() as u32;
        let alpha = 255 - (dist * 255 / ((w - 60) / 2)).min(255);
        let r = ((COLOR_BRAND_PRIMARY >> 16) & 0xFF) * alpha / 255;
        let g = ((COLOR_BRAND_PRIMARY >> 8) & 0xFF) * alpha / 255;
        let b = (COLOR_BRAND_PRIMARY & 0xFF) * alpha / 255;
        put_pixel(x + 30 + dx, y, 0xFF000000 | (r << 16) | (g << 8) | b);
    }
}

fn draw_features(x: u32, y: u32, _w: u32) {
    let features: [(&[u8], u32); 4] = [
        (b"Privacy First - Zero tracking, zero telemetry", COLOR_BRAND_PRIMARY),
        (b"RAM Only - No persistence, clean slate on reboot", SUCCESS),
        (b"Anonymous by Default - NYM Mixnet integration", COLOR_PURPLE),
        (b"Post-Quantum Ready - Future-proof cryptography", COLOR_ORANGE),
    ];
    for (i, (feat, color)) in features.iter().enumerate() {
        let fy = y + (i as u32) * 26;
        draw_bullet(x + 28, fy + 5, *color);
        text::draw(x + 44, fy, feat, TEXT_SECONDARY);
    }
}

fn draw_footer(x: u32, y: u32, w: u32) {
    fill_rect(x + 28, y - 10, w - 56, 1, COLOR_BRAND_SECONDARY);
    text::draw(x + 28, y + 5, b"(C) 2026 N\xd8NOS Project", TEXT_SECONDARY);
    text::draw(x + w - 140, y + 5, b"nonos.systems", ACCENT);
}

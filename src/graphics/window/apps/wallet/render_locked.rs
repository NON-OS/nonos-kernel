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

use super::render::{COLOR_ACCENT, COLOR_BG, COLOR_BORDER, COLOR_GREEN, COLOR_TEXT_WHITE};
use super::state::{PASSWORD_FOCUSED, PASSWORD_LEN};
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::draw_string;
use core::sync::atomic::Ordering;

pub(super) fn draw_locked_view(x: u32, y: u32, w: u32, h: u32) {
    let cx = x + w / 2;
    let cy = y + h / 2;
    for gy in 0..h {
        let s = ((gy as f32 / h as f32) * 30.0) as u8;
        fill_rect(
            x,
            y + gy,
            w,
            1,
            0xFF000000 | ((s as u32) << 16) | ((s as u32) << 8) | (s as u32),
        );
    }
    draw_rounded_card(cx - 160, cy - 120, 320, 260, 0xFF2C2C2E);
    fill_rect(cx - 16, cy - 100, 32, 24, 0xFF3A3A3C);
    fill_rect(cx - 20, cy - 80, 40, 28, COLOR_ACCENT);
    fill_rect(cx - 4, cy - 72, 8, 12, 0xFF005BBB);
    draw_string(cx - 60, cy - 55, b"N\xd8NOS Wallet", COLOR_ACCENT);
    draw_string(cx - 56, cy - 30, b"Enter Password", COLOR_TEXT_WHITE);
    let focused = PASSWORD_FOCUSED.load(Ordering::Relaxed);
    draw_password_field(cx - 130, cy, 260, focused);
    let pwd_len = PASSWORD_LEN.load(Ordering::Relaxed);
    for i in 0..pwd_len.min(30) {
        fill_rect(cx - 118 + (i as u32 * 8), cy + 13, 6, 6, COLOR_TEXT_WHITE);
    }
    if focused {
        fill_rect(cx - 118 + (pwd_len.min(30) as u32 * 8), cy + 8, 2, 16, COLOR_ACCENT);
    }
    draw_rounded_button(cx - 130, cy + 55, 125, 44, COLOR_ACCENT);
    draw_string(cx - 108, cy + 68, b"Unlock", COLOR_BG);
    draw_rounded_button(cx + 5, cy + 55, 125, 44, COLOR_GREEN);
    draw_string(cx + 20, cy + 68, b"New Wallet", COLOR_BG);
}

pub(super) fn draw_rounded_card(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 16u32;
    for shadow in 0..8u32 {
        fill_rect(
            x + r + shadow,
            y + shadow + 4,
            w - 2 * r,
            h,
            ((40 - shadow * 4) << 24) | 0x000000,
        );
    }
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

fn draw_password_field(x: u32, y: u32, w: u32, focused: bool) {
    let r = 10u32;
    let border = if focused { COLOR_ACCENT } else { COLOR_BORDER };
    let bg = 0xFF1C1C1E;
    fill_rect(x + r, y - 1, w - 2 * r, 34, border);
    fill_rect(x - 1, y + r - 1, w + 2, 32 - 2 * r + 2, border);
    fill_rect(x + r, y, w - 2 * r, 32, bg);
    fill_rect(x, y + r, w, 32 - 2 * r, bg);
}

pub(super) fn draw_rounded_button(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 10u32;
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

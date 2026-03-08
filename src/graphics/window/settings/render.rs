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

use core::sync::atomic::{AtomicBool, Ordering};
use crate::graphics::framebuffer::{fill_rect, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use super::state::{
    get_page, SIDEBAR_WIDTH, PAGE_PRIVACY, PAGE_NETWORK, PAGE_APPEARANCE, PAGE_SYSTEM, PAGE_POWER,
};
use super::{privacy, network, appearance, system, power};

static SETTINGS_SYNCED: AtomicBool = AtomicBool::new(false);

pub fn reset_sync_flag() {
    SETTINGS_SYNCED.store(false, Ordering::Relaxed);
}

pub(super) fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub(super) fn draw_toggle(x: u32, y: u32, enabled: bool) {
    let track_color = if enabled { 0xFF34C759 } else { 0xFF39393D };
    let h = 31u32;
    let w = 51u32;
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
                crate::graphics::framebuffer::put_pixel(px, y + r - dy, color);
                crate::graphics::framebuffer::put_pixel(px, y + r + dy, color);
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
                crate::graphics::framebuffer::put_pixel(cx + dx, cy + dy, color);
                crate::graphics::framebuffer::put_pixel(cx + dx, cy - dy, color);
                crate::graphics::framebuffer::put_pixel(cx - dx, cy + dy, color);
                crate::graphics::framebuffer::put_pixel(cx - dx, cy - dy, color);
            }
        }
    }
}

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    if !SETTINGS_SYNCED.swap(true, Ordering::Relaxed) {
        privacy::sync_from_system();
        network::sync_from_system();
    }

    let page = get_page();

    draw_sidebar(x, y, h, page);

    let content_x = x + SIDEBAR_WIDTH;
    let content_w = w - SIDEBAR_WIDTH;

    draw_header(content_x, y, content_w, page);

    match page {
        PAGE_PRIVACY => privacy::draw(content_x, y + 45, content_w),
        PAGE_NETWORK => network::draw(content_x, y + 45, content_w),
        PAGE_APPEARANCE => appearance::draw(content_x, y + 45, content_w),
        PAGE_SYSTEM => system::draw(content_x, y + 45, content_w),
        PAGE_POWER => power::draw(content_x, y + 45, content_w),
        _ => system::draw(content_x, y + 45, content_w),
    }

    draw_footer(content_x, y, content_w, h);
}

fn draw_sidebar(x: u32, y: u32, h: u32, current_page: u8) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, 0xFF1C1C1E);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, 0xFF38383A);

    draw_string(x + 16, y + 16, b"Settings", 0xFF8E8E93);

    let icons: [u8; 5] = [0x1F, 0x57, 0x40, 0x2A, 0x26];
    let categories: [&[u8]; 5] = [b"Privacy", b"Network", b"Wallpapers", b"System", b"Power"];
    let colors: [u32; 5] = [0xFF5856D6, 0xFF007AFF, 0xFFFF9500, 0xFF8E8E93, 0xFFFF3B30];

    for (i, cat) in categories.iter().enumerate() {
        let ty = y + 50 + (i as u32) * 44;
        let is_sel = current_page == i as u8;

        if is_sel {
            draw_rounded_selection(x + 8, ty, SIDEBAR_WIDTH - 16, 36, 0xFF3A3A3C);
        }

        fill_rect(x + 16, ty + 6, 24, 24, colors[i]);
        draw_string(x + 16 + 7, ty + 12, &[icons[i]], 0xFFFFFFFF);

        let text_color = if is_sel { COLOR_TEXT_WHITE } else { 0xFFAEAEB2 };
        draw_string(x + 48, ty + 12, cat, text_color);
    }
}

fn draw_rounded_selection(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 8u32;
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, r, h - 2 * r, color);
    fill_rect(x + w - r, y + r, r, h - 2 * r, color);
    for corner in 0..4u32 {
        let (cx, cy) = match corner {
            0 => (x + r, y + r),
            1 => (x + w - r - 1, y + r),
            2 => (x + r, y + h - r - 1),
            _ => (x + w - r - 1, y + h - r - 1),
        };
        for dy in 0..=r {
            for dx in 0..=r {
                if dx * dx + dy * dy <= r * r {
                    let (px, py) = match corner {
                        0 => (cx - dx, cy - dy),
                        1 => (cx + dx, cy - dy),
                        2 => (cx - dx, cy + dy),
                        _ => (cx + dx, cy + dy),
                    };
                    crate::graphics::framebuffer::put_pixel(px, py, color);
                }
            }
        }
    }
}

fn draw_header(x: u32, y: u32, w: u32, page: u8) {
    for gy in 0..50u32 {
        let alpha = 255 - (gy * 3).min(80);
        let shade = 28 + (gy / 3) as u8;
        let color = (alpha << 24) | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    let header: &[u8] = match page {
        PAGE_PRIVACY => b"Privacy",
        PAGE_NETWORK => b"Network",
        PAGE_APPEARANCE => b"Wallpapers",
        PAGE_SYSTEM => b"System",
        PAGE_POWER => b"Power",
        _ => b"System",
    };
    draw_string(x + 20, y + 16, header, COLOR_TEXT_WHITE);
    fill_rect(x, y + 49, w, 1, 0xFF38383A);
}

fn draw_footer(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y + h - 40, w, 1, 0xFF38383A);
    for gy in 0..39u32 {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + h - 39 + gy, w, 1, color);
    }
    draw_string(x + 20, y + h - 26, b"N\xd8NOS", 0xFF007AFF);
    draw_string(x + 68, y + h - 26, b"v1.0.0", 0xFF48484A);
    draw_string(x + w - 140, y + h - 26, b"ZeroState Mode", 0xFF34C759);
}

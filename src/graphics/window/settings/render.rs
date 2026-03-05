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
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
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
    let color = if enabled { COLOR_GREEN } else { 0xFF4A5568 };
    fill_rect(x, y, 50, 26, color);
    let knob_x = if enabled { x + 27 } else { x + 3 };
    fill_rect(knob_x, y + 3, 20, 20, COLOR_TEXT_WHITE);
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
    fill_rect(x, y, SIDEBAR_WIDTH, h, 0xFF161B22);
    fill_rect(x, y, SIDEBAR_WIDTH, 30, 0xFF21262D);
    draw_string(x + 8, y + 8, b"Settings", 0xFF7D8590);

    let categories: [&[u8]; 5] = [b"Privacy", b"Network", b"Appearance", b"System", b"Power"];
    for (i, cat) in categories.iter().enumerate() {
        let ty = y + 40 + (i as u32) * 35;
        let is_sel = current_page == i as u8;

        if is_sel {
            fill_rect(x, ty, SIDEBAR_WIDTH, 32, 0xFF2D333B);
            fill_rect(x, ty, 3, 32, COLOR_ACCENT);
        }

        draw_string(x + 12, ty + 8, cat, if is_sel { COLOR_TEXT_WHITE } else { 0xFF7D8590 });
    }
}

fn draw_header(x: u32, y: u32, w: u32, page: u8) {
    fill_rect(x, y, w, 40, 0xFF21262D);
    let header = match page {
        PAGE_PRIVACY => b"Privacy Settings    ",
        PAGE_NETWORK => b"Network Settings    ",
        PAGE_APPEARANCE => b"Appearance          ",
        PAGE_SYSTEM => b"System Settings     ",
        PAGE_POWER => b"Power Management    ",
        _ => b"System Settings     ",
    };
    draw_string(x + 15, y + 12, header, COLOR_ACCENT);
}

fn draw_footer(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y + h - 35, w, 35, 0xFF161B22);
    draw_string(x + 15, y + h - 25, b"N\xd8NOS v1.0.0 | ZeroState OS", 0xFF7D8590);
}

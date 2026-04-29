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

use super::header::{draw_footer, draw_header};
use super::sidebar::draw_sidebar;
use crate::graphics::font::draw_char;
use crate::graphics::window::settings::state::{
    get_page, PAGE_ACCESSIBILITY, PAGE_APPEARANCE, PAGE_DISPLAY, PAGE_KERNEL, PAGE_KEYBOARD,
    PAGE_LOCK, PAGE_MOUSE, PAGE_NETWORK, PAGE_POWER, PAGE_PRIVACY, PAGE_SOUND, PAGE_SYSTEM,
    SIDEBAR_WIDTH,
};
use crate::graphics::window::settings::{
    accessibility, appearance, display, kernel, keyboard, lock, mouse, network, power, privacy,
    sound, system,
};
use core::sync::atomic::{AtomicBool, Ordering};

static SETTINGS_SYNCED: AtomicBool = AtomicBool::new(false);

pub fn reset_sync_flag() {
    SETTINGS_SYNCED.store(false, Ordering::Relaxed);
}

pub fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
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
    let content_h = h - 45 - 40;

    draw_header(content_x, y, content_w, page);

    match page {
        PAGE_PRIVACY => privacy::draw(content_x, y + 45, content_w),
        PAGE_NETWORK => network::draw(content_x, y + 45, content_w),
        PAGE_APPEARANCE => appearance::draw(content_x, y + 45, content_w),
        PAGE_SYSTEM => system::draw(content_x, y + 45, content_w),
        PAGE_POWER => power::draw(content_x, y + 45, content_w),
        PAGE_KERNEL => kernel::draw(content_x, y + 45, content_w),
        PAGE_DISPLAY => display::draw(content_x, y + 45, content_w, content_h),
        PAGE_KEYBOARD => keyboard::draw(content_x, y + 45, content_w, content_h),
        PAGE_MOUSE => mouse::draw(content_x, y + 45, content_w, content_h),
        PAGE_SOUND => sound::draw(content_x, y + 45, content_w, content_h),
        PAGE_ACCESSIBILITY => accessibility::draw(content_x, y + 45, content_w, content_h),
        PAGE_LOCK => lock::draw(content_x, y + 45, content_w, content_h),
        _ => system::draw(content_x, y + 45, content_w),
    }

    draw_footer(content_x, y, content_w, h);
}

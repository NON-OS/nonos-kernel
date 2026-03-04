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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::{fill_rect, put_pixel, dimensions};
use crate::graphics::framebuffer::{COLOR_RED, COLOR_YELLOW, COLOR_GREEN, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;
use super::state::{
    WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, TITLE_BAR_HEIGHT,
    SCROLLBAR_WIDTH, WindowType, window_type_from_u32, get_window_title,
    SnapZone,
};
use super::scroll;
use super::dialogs;
use super::notifications;
use super::calculator::draw_calculator;
use super::file_manager::draw_file_manager;
use super::text_editor::draw_text_editor;
use super::settings::draw_settings;
use super::apps::{draw_about, draw_process_manager, draw_browser, draw_wallet, draw_ecosystem};
use super::terminal::draw_terminal;

fn draw_circle(cx: u32, cy: u32, r: u32, color: u32) {
    for dy in 0..=r {
        for dx in 0..=r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(cx + dx, cy + dy, color);
                if dy > 0 { put_pixel(cx + dx, cy - dy, color); }
                if dx > 0 { put_pixel(cx - dx, cy + dy, color); }
                if dx > 0 && dy > 0 { put_pixel(cx - dx, cy - dy, color); }
            }
        }
    }
}

pub fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

fn draw_window_content(x: u32, y: u32, w: u32, h: u32, wtype: WindowType) {
    match wtype {
        WindowType::Calculator => draw_calculator(x, y, w, h),
        WindowType::FileManager => draw_file_manager(x, y, w, h),
        WindowType::TextEditor => draw_text_editor(x, y, w, h),
        WindowType::Settings => draw_settings(x, y, w, h),
        WindowType::About => draw_about(x, y, w, h),
        WindowType::ProcessManager => draw_process_manager(x, y, w, h),
        WindowType::Browser => draw_browser(x, y, w, h),
        WindowType::Terminal => draw_terminal(x, y, w, h),
        WindowType::Wallet => draw_wallet(x, y, w, h),
        WindowType::Ecosystem => draw_ecosystem(x, y, w, h),
        WindowType::None => {}
    }
}

pub fn draw_window(idx: usize) {
    if idx >= MAX_WINDOWS {
        return;
    }
    if !WINDOWS[idx].active.load(Ordering::Relaxed) {
        return;
    }
    if WINDOWS[idx].minimized.load(Ordering::Relaxed) {
        return;
    }

    let x = WINDOWS[idx].x.load(Ordering::Relaxed) as u32;
    let y = WINDOWS[idx].y.load(Ordering::Relaxed) as u32;
    let w = WINDOWS[idx].width.load(Ordering::Relaxed);
    let h = WINDOWS[idx].height.load(Ordering::Relaxed);
    let wtype = window_type_from_u32(WINDOWS[idx].window_type.load(Ordering::Relaxed));
    let is_focused = FOCUSED_WINDOW.load(Ordering::Relaxed) == idx;

    if is_focused {
        fill_rect(x + 6, y + 6, w, h, 0x30000000);
        fill_rect(x + 5, y + 5, w, h, 0x25000000);
        fill_rect(x + 4, y + 4, w, h, 0x20000000);
        fill_rect(x + 3, y + 3, w, h, 0x18000000);
        fill_rect(x + 2, y + 2, w, h, 0x10000000);
    } else {
        fill_rect(x + 3, y + 3, w, h, 0x20000000);
        fill_rect(x + 2, y + 2, w, h, 0x15000000);
    }

    let bg_color = if is_focused { 0xFF1C2128 } else { 0xFF161B22 };
    fill_rect(x, y, w, h, bg_color);

    let title_color = if is_focused { 0xFF2D333B } else { 0xFF21262D };
    fill_rect(x, y, w, TITLE_BAR_HEIGHT, title_color);

    if is_focused {
        fill_rect(x, y, w, 1, 0xFF3D434B);
    }

    let btn_y = y + 14;
    draw_circle(x + 16, btn_y, 6, COLOR_RED);
    draw_circle(x + 36, btn_y, 6, COLOR_YELLOW);
    draw_circle(x + 56, btn_y, 6, COLOR_GREEN);

    if WINDOWS[idx].maximized.load(Ordering::Relaxed) {
        let bx = x + 56;
        let by = btn_y;
        fill_rect(bx - 2, by - 2, 5, 5, 0xFF0A4F0A);
    }

    let title = get_window_title(wtype);
    let title_x = x + 76;
    for (i, &ch) in title.iter().enumerate() {
        draw_char(title_x + (i as u32) * 8, y + 8, ch, COLOR_TEXT_WHITE);
    }

    let content_y = y + TITLE_BAR_HEIGHT;
    let content_h = h - TITLE_BAR_HEIGHT;
    draw_window_content(x, content_y, w, content_h, wtype);

    if scroll::needs_vertical(idx, content_h) {
        scroll::draw_vertical(idx, x + w - SCROLLBAR_WIDTH, content_y, content_h);
    }
}

fn draw_snap_preview() {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused >= MAX_WINDOWS {
        return;
    }

    if !WINDOWS[focused].dragging.load(Ordering::Relaxed) {
        return;
    }

    let pending = SnapZone::from_u8(WINDOWS[focused].pending_snap.load(Ordering::Relaxed));
    if pending == SnapZone::None {
        return;
    }

    let (screen_w, screen_h) = dimensions();
    let taskbar_height = 40u32;
    let menu_bar_height = 32u32;
    let usable_height = screen_h - taskbar_height - menu_bar_height;
    let half_width = screen_w / 2;
    let half_height = usable_height / 2;

    let preview_color = 0x4058A6FF;

    let (x, y, w, h) = match pending {
        SnapZone::Left => (0, menu_bar_height, half_width, usable_height),
        SnapZone::Right => (half_width, menu_bar_height, half_width, usable_height),
        SnapZone::Top => (0, menu_bar_height, screen_w, usable_height),
        SnapZone::TopLeft => (0, menu_bar_height, half_width, half_height),
        SnapZone::TopRight => (half_width, menu_bar_height, half_width, half_height),
        SnapZone::BottomLeft => (0, menu_bar_height + half_height, half_width, half_height),
        SnapZone::BottomRight => (half_width, menu_bar_height + half_height, half_width, half_height),
        SnapZone::None => return,
    };

    fill_rect(x, y, w, h, preview_color);

    let border_color = 0xFF58A6FF;
    fill_rect(x, y, w, 2, border_color);
    fill_rect(x, y + h - 2, w, 2, border_color);
    fill_rect(x, y, 2, h, border_color);
    fill_rect(x + w - 2, y, 2, h, border_color);
}

pub fn draw_all() {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);

    draw_snap_preview();

    for i in 0..MAX_WINDOWS {
        if i != focused && WINDOWS[i].active.load(Ordering::Relaxed)
            && !WINDOWS[i].minimized.load(Ordering::Relaxed) {
            draw_window(i);
        }
    }

    if focused < MAX_WINDOWS && WINDOWS[focused].active.load(Ordering::Relaxed)
        && !WINDOWS[focused].minimized.load(Ordering::Relaxed) {
        draw_window(focused);
    }

    notifications::draw();
    dialogs::draw();
}

pub fn redraw_focused() {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused < MAX_WINDOWS {
        draw_window(focused);
    }
}

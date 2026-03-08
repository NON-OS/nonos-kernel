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
use crate::graphics::framebuffer::COLOR_TEXT_WHITE;
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

const BTN_CLOSE: u32 = 0xFFFF5F57;
const BTN_MIN: u32 = 0xFFFEBC2E;
const BTN_MAX: u32 = 0xFF28C840;
const CORNER_RADIUS: u32 = 12;

fn draw_circle(cx: u32, cy: u32, r: u32, color: u32) {
    let r_sq = (r * r) as i32;
    for dy in 0..=r {
        for dx in 0..=r {
            let dist = (dx * dx + dy * dy) as i32;
            if dist <= r_sq {
                let alpha = if dist > (r_sq - r as i32 * 2) {
                    ((r_sq - dist) as u32 * 255 / (r * 2)) as u32
                } else { 255 };
                let blended = blend_alpha(color, alpha);
                put_pixel(cx + dx, cy + dy, blended);
                if dy > 0 { put_pixel(cx + dx, cy - dy, blended); }
                if dx > 0 { put_pixel(cx - dx, cy + dy, blended); }
                if dx > 0 && dy > 0 { put_pixel(cx - dx, cy - dy, blended); }
            }
        }
    }
}

fn blend_alpha(color: u32, alpha: u32) -> u32 {
    let a = ((color >> 24) & 0xFF) * alpha / 255;
    (a << 24) | (color & 0x00FFFFFF)
}

fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, r, h - 2 * r, color);
    fill_rect(x + w - r, y + r, r, h - 2 * r, color);
    draw_corner(x + r, y + r, r, color, 0);
    draw_corner(x + w - r - 1, y + r, r, color, 1);
    draw_corner(x + r, y + h - r - 1, r, color, 2);
    draw_corner(x + w - r - 1, y + h - r - 1, r, color, 3);
}

fn draw_corner(cx: u32, cy: u32, r: u32, color: u32, quadrant: u8) {
    let r_sq = (r * r) as i32;
    for dy in 0..=r {
        for dx in 0..=r {
            let dist = (dx * dx + dy * dy) as i32;
            if dist <= r_sq {
                let (px, py) = match quadrant {
                    0 => (cx - dx, cy - dy),
                    1 => (cx + dx, cy - dy),
                    2 => (cx - dx, cy + dy),
                    _ => (cx + dx, cy + dy),
                };
                put_pixel(px, py, color);
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

    for shadow in 0..6u32 {
        let offset = shadow + 2;
        let alpha = if is_focused { 40 - shadow * 5 } else { 20 - shadow * 3 };
        let shadow_color = (alpha << 24) | 0x000000;
        fill_rect(x + offset, y + offset + shadow, w, h - shadow, shadow_color);
    }

    let bg = if is_focused { 0xFF1C1C1E } else { 0xFF2C2C2E };
    draw_rounded_rect(x, y, w, h, CORNER_RADIUS, bg);

    let title_bg = if is_focused { 0xFF3A3A3C } else { 0xFF2C2C2E };
    fill_rect(x + CORNER_RADIUS, y, w - 2 * CORNER_RADIUS, TITLE_BAR_HEIGHT, title_bg);
    fill_rect(x, y + CORNER_RADIUS, CORNER_RADIUS, TITLE_BAR_HEIGHT - CORNER_RADIUS, title_bg);
    fill_rect(x + w - CORNER_RADIUS, y + CORNER_RADIUS, CORNER_RADIUS, TITLE_BAR_HEIGHT - CORNER_RADIUS, title_bg);
    draw_corner(x + CORNER_RADIUS, y + CORNER_RADIUS, CORNER_RADIUS, title_bg, 0);
    draw_corner(x + w - CORNER_RADIUS - 1, y + CORNER_RADIUS, CORNER_RADIUS, title_bg, 1);

    if is_focused {
        for gy in 0..2u32 {
            let alpha = 12 - gy * 4;
            fill_rect(x + CORNER_RADIUS, y + gy, w - 2 * CORNER_RADIUS, 1, (alpha << 24) | 0xFFFFFF);
        }
    }

    fill_rect(x, y + TITLE_BAR_HEIGHT - 1, w, 1, 0x20000000);

    let btn_y = y + 14;
    draw_circle(x + 18, btn_y, 6, BTN_CLOSE);
    draw_circle(x + 40, btn_y, 6, BTN_MIN);
    draw_circle(x + 62, btn_y, 6, BTN_MAX);

    if WINDOWS[idx].maximized.load(Ordering::Relaxed) {
        for dy in 0..3u32 {
            for dx in 0..3u32 {
                put_pixel(x + 60 + dx, btn_y - 1 + dy, 0xFF0D5F0D);
            }
        }
    }

    let title = get_window_title(wtype);
    let title_len = title.len() as u32;
    let title_x = x + (w / 2) - (title_len * 8 / 2);
    let title_color = if is_focused { COLOR_TEXT_WHITE } else { 0xFF8E8E93 };
    for (i, &ch) in title.iter().enumerate() {
        draw_char(title_x + (i as u32) * 8, y + 9, ch, title_color);
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

    let preview_color = 0x3066FFFF;

    let (px, py, pw, ph) = match pending {
        SnapZone::Left => (0, menu_bar_height, half_width, usable_height),
        SnapZone::Right => (half_width, menu_bar_height, half_width, usable_height),
        SnapZone::Top => (0, menu_bar_height, screen_w, usable_height),
        SnapZone::TopLeft => (0, menu_bar_height, half_width, half_height),
        SnapZone::TopRight => (half_width, menu_bar_height, half_width, half_height),
        SnapZone::BottomLeft => (0, menu_bar_height + half_height, half_width, half_height),
        SnapZone::BottomRight => (half_width, menu_bar_height + half_height, half_width, half_height),
        SnapZone::None => return,
    };

    fill_rect(px, py, pw, ph, preview_color);

    let border = 0xFF66FFFF;
    fill_rect(px, py, pw, 2, border);
    fill_rect(px, py + ph - 2, pw, 2, border);
    fill_rect(px, py, 2, ph, border);
    fill_rect(px + pw - 2, py, 2, ph, border);
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

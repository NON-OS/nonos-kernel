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

use super::constants::*;
use super::content::draw_window_content;
use super::frame::draw_window_frame;
use super::shadow::draw_soft_shadow;
use super::snap::draw_snap_preview;
use super::titlebar::draw_titlebar;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::state::get_window_title;
use crate::graphics::window::state::{
    window_type_from_u32, FOCUSED_WINDOW, MAX_WINDOWS, SCROLLBAR_WIDTH, TITLE_BAR_HEIGHT, WINDOWS,
};
use crate::graphics::window::{dialogs, notifications, scroll};
use core::sync::atomic::Ordering;

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
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed) == idx;
    let maximized = WINDOWS[idx].maximized.load(Ordering::Relaxed);
    draw_soft_shadow(x, y, w, h, focused);
    draw_window_frame(x, y, w, h, focused);
    draw_titlebar(x, y, w, focused, get_window_title(wtype), maximized);
    let content_y = y + TITLE_BAR_HEIGHT;
    let content_h = h.saturating_sub(TITLE_BAR_HEIGHT);
    let bg = if focused { WIN_BG_FOCUSED } else { WIN_BG_UNFOCUSED };
    fill_rect(x, content_y, w, content_h, bg);
    draw_window_content(x, content_y, w, content_h, wtype);
    if scroll::needs_vertical(idx, content_h) {
        scroll::draw_vertical(idx, x + w - SCROLLBAR_WIDTH, content_y, content_h);
    }
}

pub fn draw_all() {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    draw_snap_preview();
    for i in 0..MAX_WINDOWS {
        if i != focused
            && WINDOWS[i].active.load(Ordering::Relaxed)
            && !WINDOWS[i].minimized.load(Ordering::Relaxed)
        {
            draw_window(i);
        }
    }
    if focused < MAX_WINDOWS
        && WINDOWS[focused].active.load(Ordering::Relaxed)
        && !WINDOWS[focused].minimized.load(Ordering::Relaxed)
    {
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

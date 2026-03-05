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
use crate::graphics::framebuffer::dimensions;
use super::state::{WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, TITLE_BAR_HEIGHT};
use super::scroll;
use super::dialogs;
use super::notifications;
use super::input_snap::{detect_snap_zone, restore_from_snap};
use super::input_resize::handle_resize;
use super::input_keys;
use super::input_click::check_window_click;

pub use super::input_focus::{
    is_editor_focused, is_terminal_focused, is_browser_focused,
    is_wallet_focused, is_ecosystem_focused, is_file_manager_focused, is_text_input_focused,
};

pub fn handle_click(mx: i32, my: i32, pressed: bool) -> bool {
    if pressed && dialogs::is_active() {
        dialogs::handle_click(mx, my);
        return true;
    }

    if pressed && notifications::handle_click(mx, my) {
        return true;
    }

    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);

    if focused < MAX_WINDOWS && WINDOWS[focused].active.load(Ordering::Relaxed)
        && !WINDOWS[focused].minimized.load(Ordering::Relaxed) {
        if check_window_click(focused, mx, my, pressed) {
            return true;
        }
    }

    for i in (0..MAX_WINDOWS).rev() {
        if i != focused && WINDOWS[i].active.load(Ordering::Relaxed)
            && !WINDOWS[i].minimized.load(Ordering::Relaxed) {
            if check_window_click(i, mx, my, pressed) {
                return true;
            }
        }
    }

    false
}

pub fn handle_drag(mx: i32, my: i32) {
    let (screen_w, screen_h) = dimensions();

    for i in 0..MAX_WINDOWS {
        if !WINDOWS[i].active.load(Ordering::Relaxed) {
            continue;
        }

        if WINDOWS[i].resizing.load(Ordering::Relaxed) {
            handle_resize(i, mx, my, screen_w, screen_h);
            continue;
        }

        if WINDOWS[i].dragging.load(Ordering::Relaxed) {
            if WINDOWS[i].snapped.load(Ordering::Relaxed) {
                restore_from_snap(i, mx);
            }

            let offset_x = WINDOWS[i].drag_offset_x.load(Ordering::Relaxed);
            let offset_y = WINDOWS[i].drag_offset_y.load(Ordering::Relaxed);
            let w = WINDOWS[i].width.load(Ordering::Relaxed) as i32;

            let new_x = (mx - offset_x).max(60 - w).min(screen_w as i32 - 60);
            let new_y = (my - offset_y).max(32).min(screen_h as i32 - 40);

            WINDOWS[i].x.store(new_x, Ordering::Relaxed);
            WINDOWS[i].y.store(new_y, Ordering::Relaxed);

            let snap_zone = detect_snap_zone(mx, my, screen_w, screen_h);
            WINDOWS[i].pending_snap.store(snap_zone as u8, Ordering::Relaxed);
        }

        if scroll::is_dragging(i) {
            let y = WINDOWS[i].y.load(Ordering::Relaxed);
            let h = WINDOWS[i].height.load(Ordering::Relaxed);
            let content_y = (y + TITLE_BAR_HEIGHT as i32) as u32;
            let content_h = h - TITLE_BAR_HEIGHT;
            scroll::handle_drag(i, content_y, content_h, my);
        }
    }
}

pub fn is_dragging() -> bool {
    for i in 0..MAX_WINDOWS {
        if WINDOWS[i].active.load(Ordering::Relaxed) {
            if WINDOWS[i].dragging.load(Ordering::Relaxed)
                || WINDOWS[i].resizing.load(Ordering::Relaxed)
                || scroll::is_dragging(i)
            {
                return true;
            }
        }
    }
    false
}

pub fn handle_key(ch: u8) {
    input_keys::handle_key(ch);
}

pub fn browser_special_key(key: crate::graphics::window::text_editor::SpecialKey) {
    input_keys::browser_special_key(key);
}

pub fn wallet_special_key(key: crate::graphics::window::text_editor::SpecialKey) {
    input_keys::wallet_special_key(key);
}

pub fn ecosystem_special_key(key: crate::graphics::window::text_editor::SpecialKey) {
    input_keys::ecosystem_special_key(key);
}

pub fn file_manager_special_key(key: u8) -> bool {
    input_keys::file_manager_special_key(key)
}

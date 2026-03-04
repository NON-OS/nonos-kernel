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
use super::state::{
    WINDOWS, FOCUSED_WINDOW, TITLE_BAR_HEIGHT,
    SCROLLBAR_WIDTH, WindowType, window_type_from_u32,
    RESIZE_BORDER, SnapZone,
};
use super::scroll;
use super::manager;
use super::calculator_input::handle_calculator_click;
use super::file_manager::handle_file_manager_click;
use super::text_editor::handle_text_editor_click;
use super::settings::handle_settings_click;
use super::apps::{handle_process_manager_click, handle_browser_click, handle_wallet_click, handle_ecosystem_click};
use super::terminal::handle_terminal_click;
use super::input_snap::apply_snap;
use super::input_resize::detect_resize_edge;

pub(super) fn check_window_click(idx: usize, mx: i32, my: i32, pressed: bool) -> bool {
    let x = WINDOWS[idx].x.load(Ordering::Relaxed);
    let y = WINDOWS[idx].y.load(Ordering::Relaxed);
    let w = WINDOWS[idx].width.load(Ordering::Relaxed) as i32;
    let h = WINDOWS[idx].height.load(Ordering::Relaxed) as i32;
    let wtype = window_type_from_u32(WINDOWS[idx].window_type.load(Ordering::Relaxed));

    let edge = detect_resize_edge(x, y, w, h, mx, my);
    let in_bounds = mx >= x - RESIZE_BORDER && mx <= x + w + RESIZE_BORDER
        && my >= y - RESIZE_BORDER && my <= y + h + RESIZE_BORDER;

    if !in_bounds {
        if !pressed {
            WINDOWS[idx].dragging.store(false, Ordering::Relaxed);
            WINDOWS[idx].resizing.store(false, Ordering::Relaxed);
            scroll::stop_dragging(idx);
        }
        return false;
    }

    let is_maximized = WINDOWS[idx].maximized.load(Ordering::Relaxed);

    if pressed {
        FOCUSED_WINDOW.store(idx, Ordering::Relaxed);

        if edge != super::state::ResizeEdge::None && !is_maximized {
            WINDOWS[idx].resizing.store(true, Ordering::Relaxed);
            WINDOWS[idx].resize_edge.store(edge as u8, Ordering::Relaxed);
            WINDOWS[idx].resize_start_x.store(x, Ordering::Relaxed);
            WINDOWS[idx].resize_start_y.store(y, Ordering::Relaxed);
            WINDOWS[idx].resize_start_w.store(w as u32, Ordering::Relaxed);
            WINDOWS[idx].resize_start_h.store(h as u32, Ordering::Relaxed);
            WINDOWS[idx].drag_offset_x.store(mx, Ordering::Relaxed);
            WINDOWS[idx].drag_offset_y.store(my, Ordering::Relaxed);
            return true;
        }

        if handle_title_bar_buttons(idx, x, y, mx, my) {
            return true;
        }

        if my < y + TITLE_BAR_HEIGHT as i32 {
            handle_title_bar_drag(idx, x, y, w, mx, my, is_maximized);
            WINDOWS[idx].dragging.store(true, Ordering::Relaxed);
        } else {
            if handle_content_click(idx, x, y, w, h, mx, my, wtype) {
                return true;
            }
        }
    } else {
        let pending = SnapZone::from_u8(WINDOWS[idx].pending_snap.load(Ordering::Relaxed));
        if WINDOWS[idx].dragging.load(Ordering::Relaxed) && pending != SnapZone::None {
            let (screen_w, screen_h) = dimensions();
            apply_snap(idx, pending, screen_w, screen_h);
        }
        WINDOWS[idx].pending_snap.store(0, Ordering::Relaxed);
        WINDOWS[idx].dragging.store(false, Ordering::Relaxed);
        WINDOWS[idx].resizing.store(false, Ordering::Relaxed);
        scroll::stop_dragging(idx);
    }

    true
}

fn handle_title_bar_buttons(idx: usize, x: i32, y: i32, mx: i32, my: i32) -> bool {
    let close_x = x + 16;
    let close_y = y + 14;
    if (mx - close_x).abs() <= 8 && (my - close_y).abs() <= 8 {
        manager::close(idx);
        return true;
    }

    let min_x = x + 36;
    let min_y = y + 14;
    if (mx - min_x).abs() <= 8 && (my - min_y).abs() <= 8 {
        manager::minimize(idx);
        return true;
    }

    let max_x = x + 56;
    let max_y = y + 14;
    if (mx - max_x).abs() <= 8 && (my - max_y).abs() <= 8 {
        manager::maximize(idx);
        return true;
    }

    false
}

fn handle_title_bar_drag(idx: usize, x: i32, y: i32, w: i32, mx: i32, my: i32, is_maximized: bool) {
    if is_maximized {
        manager::maximize(idx);
        let new_x = WINDOWS[idx].x.load(Ordering::Relaxed);
        let new_w = WINDOWS[idx].width.load(Ordering::Relaxed) as i32;
        let centered_x = if new_x > 0 { (mx - new_w / 2).max(new_x.min(60)) } else { mx - new_w / 2 };
        WINDOWS[idx].x.store(centered_x.max(60), Ordering::Relaxed);
        WINDOWS[idx].drag_offset_x.store(new_w / 2, Ordering::Relaxed);
        WINDOWS[idx].drag_offset_y.store(my - y, Ordering::Relaxed);
    } else {
        let _ = w;
        WINDOWS[idx].drag_offset_x.store(mx - x, Ordering::Relaxed);
        WINDOWS[idx].drag_offset_y.store(my - y, Ordering::Relaxed);
    }
}

fn handle_content_click(idx: usize, x: i32, y: i32, w: i32, h: i32, mx: i32, my: i32, wtype: WindowType) -> bool {
    let content_y = (y + TITLE_BAR_HEIGHT as i32) as u32;
    let content_h = (h - TITLE_BAR_HEIGHT as i32) as u32;
    let scrollbar_x = (x + w - SCROLLBAR_WIDTH as i32) as u32;

    if scroll::needs_vertical(idx, content_h) {
        if scroll::handle_vertical_click(idx, scrollbar_x, content_y, content_h, mx, my, true) {
            return true;
        }
    }

    let content_y = y + TITLE_BAR_HEIGHT as i32;
    let content_h = h - TITLE_BAR_HEIGHT as i32;
    dispatch_app_click(wtype, x as u32, content_y as u32, w as u32, content_h as u32, mx, my);
    false
}

fn dispatch_app_click(wtype: WindowType, x: u32, y: u32, w: u32, h: u32, mx: i32, my: i32) {
    match wtype {
        WindowType::Calculator => {
            handle_calculator_click(x, y, mx, my);
        }
        WindowType::Settings => {
            handle_settings_click(x, y, w, mx, my);
        }
        WindowType::FileManager => {
            handle_file_manager_click(x, y, w, mx, my);
        }
        WindowType::TextEditor => {
            handle_text_editor_click(x, y, w, h, mx, my);
        }
        WindowType::ProcessManager => {
            handle_process_manager_click(x, y, w, h, mx, my);
        }
        WindowType::Terminal => {
            handle_terminal_click(x, y, w, h, mx, my);
        }
        WindowType::Browser => {
            handle_browser_click(x, y, w, h, mx, my);
        }
        WindowType::Wallet => {
            handle_wallet_click(x, y, w, h, mx, my);
        }
        WindowType::Ecosystem => {
            handle_ecosystem_click(x, y, w, h, mx, my);
        }
        _ => {}
    }
}

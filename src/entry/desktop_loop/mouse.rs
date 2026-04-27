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

use super::menu_actions::handle_context_menu_action;
use super::state::{
    set_needs_redraw, NEEDS_REDRAW, PREV_LEFT_BUTTON, PREV_RIGHT_BUTTON, WAS_DRAGGING,
};
use crate::entry::context::get_context_menu_type;
use crate::graphics::window::context_menu::{self, show as show_menu, ContextMenuType};
use crate::graphics::{cursor, desktop, framebuffer, window};

pub fn handle_mouse_input(old_mx: &mut i32, old_my: &mut i32) {
    handle_scroll();
    if !crate::input::poll_mouse_unified() {
        return;
    }
    let (mx, my) = crate::input::mouse_position_unified();
    let left_btn = crate::input::left_button_pressed();
    let right_btn = crate::input::right_button_pressed();
    if context_menu::is_visible() {
        context_menu::update_hover(mx, my);
    }
    handle_clicks(mx, my, left_btn, right_btn);
    handle_dragging(mx, my);
    handle_cursor_update(mx, my, old_mx, old_my);
}

fn handle_scroll() {
    let scroll_delta = crate::input::mouse::take_scroll_delta();
    if scroll_delta != 0 {
        let focused = window::FOCUSED_WINDOW.load(core::sync::atomic::Ordering::Relaxed);
        if focused < window::MAX_WINDOWS {
            window::scroll_window_by(focused, 0, scroll_delta * 3);
            set_needs_redraw();
        }
    }
}

fn handle_clicks(mx: i32, my: i32, left_btn: bool, right_btn: bool) {
    unsafe {
        if left_btn && !PREV_LEFT_BUTTON {
            if context_menu::is_visible() {
                if let Some(action) = context_menu::handle_click(mx, my) {
                    handle_context_menu_action(action);
                }
                NEEDS_REDRAW = true;
            } else if !window::handle_click(mx, my, true) {
                if desktop::handle_menu_bar_click(mx, my) {
                    NEEDS_REDRAW = true;
                } else if desktop::handle_sidebar_click(mx, my) {
                    NEEDS_REDRAW = true;
                } else if desktop::handle_dock_click(mx, my) {
                    NEEDS_REDRAW = true;
                } else if let Some((path, is_dir, should_open)) =
                    desktop::handle_desktop_icon_click(mx, my)
                {
                    if should_open {
                        if is_dir {
                            if let Some(name) = path.rsplit('/').next() {
                                desktop::desktop_navigate_into(name);
                            }
                        } else {
                            window::open(window::WindowType::TextEditor);
                            window::text_editor_open_file(path);
                        }
                    }
                    NEEDS_REDRAW = true;
                }
            } else {
                NEEDS_REDRAW = true;
            }
        } else if !left_btn && PREV_LEFT_BUTTON {
            window::handle_click(mx, my, false);
            desktop::handle_desktop_icon_drag_end();
        }
        PREV_LEFT_BUTTON = left_btn;
        if right_btn && !PREV_RIGHT_BUTTON {
            context_menu::hide();
            let menu_type = get_context_menu_type(mx, my);
            if menu_type != ContextMenuType::None {
                show_menu(mx, my, menu_type);
                NEEDS_REDRAW = true;
            }
        }
        PREV_RIGHT_BUTTON = right_btn;
    }
}

fn handle_dragging(mx: i32, my: i32) {
    let is_window_dragging = window::is_dragging();
    let is_icon_dragging = desktop::is_desktop_icon_dragging();
    let is_dragging = is_window_dragging || is_icon_dragging;
    if is_window_dragging {
        window::handle_drag(mx, my);
        unsafe {
            WAS_DRAGGING = true;
        }
    }
    if is_icon_dragging {
        desktop::handle_desktop_icon_drag(mx, my);
        unsafe {
            WAS_DRAGGING = true;
        }
    }
    if !is_dragging && unsafe { WAS_DRAGGING } {
        unsafe {
            NEEDS_REDRAW = true;
            WAS_DRAGGING = false;
        }
    }
}

fn handle_cursor_update(mx: i32, my: i32, old_mx: &mut i32, old_my: &mut i32) {
    if mx != *old_mx || my != *old_my {
        let is_dragging = window::is_dragging() || desktop::is_desktop_icon_dragging();
        unsafe {
            if NEEDS_REDRAW || is_dragging {
                framebuffer::double_buffer::disable();
                cursor::erase();
                framebuffer::double_buffer::enable();
                desktop::redraw_background();
                window::draw_all();
                context_menu::draw();
                cursor::draw(mx, my);
                framebuffer::swap_buffers();
                NEEDS_REDRAW = false;
            } else {
                framebuffer::double_buffer::disable();
                cursor::draw(mx, my);
                framebuffer::double_buffer::enable();
            }
        }
        *old_mx = mx;
        *old_my = my;
    }
}

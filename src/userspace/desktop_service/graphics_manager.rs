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

use crate::graphics::desktop::api;
use crate::graphics::framebuffer::swap_buffers;

static mut LAST_CLOCK_UPDATE: u64 = 0;
static mut FRAME_COUNT: u64 = 0;

pub fn initialize_graphics() {
    crate::graphics::init::initialize_graphics_subsystem();
    render_desktop();
}

pub fn render_desktop() {
    unsafe {
        FRAME_COUNT += 1;
    }

    api::draw_all();
    swap_buffers();
}

pub fn update_animations() {
    if unsafe { FRAME_COUNT % 30 == 0 } {
        api::refresh_desktop_icons();
    }
}

pub fn update_clock() {
    let current_time = crate::time::current_time_ms();
    let last_update = unsafe { LAST_CLOCK_UPDATE };

    if current_time - last_update >= 1000 {
        api::update_clock();
        unsafe {
            LAST_CLOCK_UPDATE = current_time;
        }
    }
}

pub fn handle_mouse_click(x: i32, y: i32, button: u8) {
    match button {
        1 => handle_left_click(x, y),
        2 => handle_right_click(x, y),
        _ => {}
    }
    render_desktop();
}

fn handle_left_click(x: i32, y: i32) {
    if api::handle_menu_bar_click(x, y) {
        return;
    }

    if api::handle_dock_click(x, y) {
        return;
    }

    if api::handle_sidebar_click(x, y) {
        return;
    }

    if let Some((path, is_dir, _)) = api::handle_desktop_icon_click(x, y) {
        if is_dir {
            api::desktop_navigate_into(path);
        } else {
            launch_application(path);
        }
        return;
    }

    api::desktop_clear_selection();
}

fn handle_right_click(x: i32, y: i32) {
    match api::handle_desktop_right_click(x, y) {
        api::DesktopAction::ShowMenu => {
            show_context_menu(x, y);
        }
        api::DesktopAction::SelectItem(path) => {
            show_item_menu(x, y, path);
        }
        _ => {}
    }
}

fn launch_application(_path: &str) {
    crate::sys::serial::print(b"[DESKTOP] Launch app: ");
    crate::sys::serial::println(_path.as_bytes());
}

fn show_context_menu(_x: i32, _y: i32) {
    crate::sys::serial::println(b"[DESKTOP] Show context menu");
}

fn show_item_menu(_x: i32, _y: i32, _path: &str) {
    crate::sys::serial::print(b"[DESKTOP] Show item menu for: ");
    crate::sys::serial::println(_path.as_bytes());
}

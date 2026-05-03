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

use super::{desktop_icons, dock, grid, menubar, sidebar};
use crate::display::framebuffer::{dimensions, COLOR_BG};
use crate::graphics::framebuffer::{fill_rect};

pub fn draw_all() {
    let (w, h) = dimensions();

    crate::sys::serial::println(b"[DRAW] wallpaper");
    if let Some(wallpaper) = crate::graphics::backgrounds::wallpaper::load_current_wallpaper() {
        crate::graphics::image::draw_wallpaper(wallpaper, w, h);
    } else {
        fill_rect(0, 0, w, h, COLOR_BG);
        grid::draw(w, h);
    }
    crate::sys::serial::println(b"[DRAW] icons");
    desktop_icons::draw(w, h);
    crate::sys::serial::println(b"[DRAW] windows");
    crate::graphics::window::draw_all();
    crate::sys::serial::println(b"[DRAW] menubar");
    menubar::draw(w);
    crate::sys::serial::println(b"[DRAW] sidebar");
    sidebar::draw(h);
    crate::sys::serial::println(b"[DRAW] dock");
    dock::draw(w, h);
    crate::sys::serial::println(b"[DRAW] cursor");
    let (mx, my) = crate::input::mouse_position_unified();
    crate::graphics::cursor::draw(mx as i32, my as i32);
    crate::sys::serial::println(b"[DRAW] done");
}

pub fn handle_menu_bar_click(mx: i32, my: i32) -> bool {
    let (w, _) = dimensions();
    menubar::handle_click(mx, my, w)
}

pub fn handle_dock_click(mx: i32, my: i32) -> bool {
    dock::handle_click(mx, my)
}

pub fn handle_sidebar_click(mx: i32, my: i32) -> bool {
    sidebar::handle_click(mx, my)
}

pub fn handle_desktop_icon_click(mx: i32, my: i32) -> Option<(&'static str, bool, bool)> {
    let (w, _) = dimensions();
    desktop_icons::handle_click(mx, my, w)
}

pub fn handle_desktop_right_click(mx: i32, my: i32) -> DesktopAction {
    let (w, _) = dimensions();
    if let Some((path, _is_dir, _)) = desktop_icons::handle_click(mx, my, w) {
        return DesktopAction::SelectItem(path);
    }
    DesktopAction::ShowMenu
}

pub fn refresh_desktop_icons() {
    desktop_icons::refresh();
}

pub fn update_clock() {
    menubar::update_clock();
}

pub fn redraw_background() {
    let (w, h) = dimensions();

    if let Some(wallpaper) = crate::graphics::backgrounds::wallpaper::load_current_wallpaper() {
        crate::graphics::image::draw_wallpaper(wallpaper, w, h);
    } else {
        fill_rect(0, 0, w, h, COLOR_BG);
        grid::draw(w, h);
    }
    desktop_icons::draw(w, h);
    menubar::draw(w);
    sidebar::draw(h);
    dock::draw(w, h);
}

#[derive(Clone, Copy)]
pub enum DesktopAction {
    None,
    ShowMenu,
    SelectItem(&'static str),
}

pub fn create_desktop_folder(name: &str) -> bool {
    let result = desktop_icons::create_folder(name);
    if result {
        desktop_icons::refresh();
    }
    result
}

pub fn create_desktop_file(name: &str) -> bool {
    let result = desktop_icons::create_file(name);
    if result {
        desktop_icons::refresh();
    }
    result
}

pub fn delete_desktop_selected() -> bool {
    let result = desktop_icons::delete_selected();
    if result {
        desktop_icons::refresh();
    }
    result
}

pub fn desktop_has_selection() -> bool {
    desktop_icons::has_selection()
}

pub fn desktop_clear_selection() {
    desktop_icons::clear_selection();
}

pub fn handle_desktop_icon_drag(mx: i32, my: i32) -> bool {
    desktop_icons::handle_drag(mx, my)
}

pub fn handle_desktop_icon_drag_end() {
    desktop_icons::handle_drag_end();
}

pub fn is_desktop_icon_dragging() -> bool {
    desktop_icons::is_dragging()
}

pub fn desktop_navigate_into(name: &str) -> bool {
    desktop_icons::navigate_into(name)
}

pub fn desktop_navigate_back() -> bool {
    desktop_icons::navigate_back()
}

pub fn desktop_is_in_subfolder() -> bool {
    desktop_icons::is_in_subfolder()
}

pub fn desktop_get_current_path() -> &'static str {
    desktop_icons::get_current_path()
}

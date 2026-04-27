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

mod api;
mod constants;
mod desktop_icons;
mod dock;
mod dock_helpers;
mod dock_icons_apps;
mod dock_icons_system;
mod grid;
mod grid_wallpaper;
pub mod logo;
mod menubar;
mod menubar_icons;
mod sidebar;
mod sidebar_icons;
mod sidebar_utils;
pub mod status;

pub use api::{
    create_desktop_file, create_desktop_folder, delete_desktop_selected, desktop_clear_selection,
    desktop_get_current_path, desktop_has_selection, desktop_is_in_subfolder,
    desktop_navigate_back, desktop_navigate_into, draw_all, handle_desktop_icon_click,
    handle_desktop_icon_drag, handle_desktop_icon_drag_end, handle_desktop_right_click,
    handle_dock_click, handle_menu_bar_click, handle_sidebar_click, is_desktop_icon_dragging,
    redraw_background, refresh_desktop_icons, update_clock, DesktopAction,
};

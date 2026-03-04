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
mod dock;
mod dock_helpers;
mod dock_icons_apps;
mod dock_icons_system;
mod grid;
mod grid_wallpaper;
mod logo;
mod menubar;
mod menubar_icons;
mod sidebar;
mod sidebar_icons;
mod sidebar_utils;
mod terminal_preview;

pub use api::{
    draw_all,
    handle_menu_bar_click,
    handle_dock_click,
    handle_sidebar_click,
    update_clock,
    redraw_background,
};

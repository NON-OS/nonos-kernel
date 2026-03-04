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

use crate::graphics::framebuffer::{fill_rect, dimensions, COLOR_BG};
use super::{grid, menubar, sidebar, dock};

pub fn draw_all() {
    let (w, h) = dimensions();

    fill_rect(0, 0, w, h, COLOR_BG);
    grid::draw(w, h);
    menubar::draw(w);
    sidebar::draw(h);
    dock::draw(w, h);
}

pub fn handle_menu_bar_click(mx: i32, my: i32) -> bool {
    menubar::handle_click(mx, my)
}

pub fn handle_dock_click(mx: i32, my: i32) -> bool {
    dock::handle_click(mx, my)
}

pub fn handle_sidebar_click(mx: i32, my: i32) -> bool {
    sidebar::handle_click(mx, my)
}

pub fn update_clock() {
    menubar::update_clock();
}

pub fn redraw_background() {
    let (w, h) = dimensions();

    fill_rect(0, 0, w, h, COLOR_BG);
    grid::draw(w, h);
    menubar::draw(w);
    sidebar::draw(h);
    dock::draw(w, h);
}

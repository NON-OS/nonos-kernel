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

/*
 * Public API for the wallet application.
 *
 * These functions are called by the window manager to render the wallet
 * interface and handle user input events. The wallet supports keyboard
 * input for password entry and special keys (arrow keys, backspace,
 * enter, tab) for navigation.
 */

use super::render;
use super::input;
use crate::graphics::window::text_editor::SpecialKey;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    render::draw(x, y, w, h);
}

pub fn handle_click(
    win_x: u32,
    win_y: u32,
    win_w: u32,
    win_h: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    input::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}

pub fn handle_key(ch: u8) {
    input::handle_key(ch);
}

pub fn handle_special_key(key: SpecialKey) {
    input::handle_special_key(key);
}

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

use super::{about, process_manager, wallet};
use crate::graphics::window::text_editor::SpecialKey;

pub fn draw_about(x: u32, y: u32, w: u32, h: u32) {
    about::draw(x, y, w, h);
}

pub fn draw_process_manager(x: u32, y: u32, w: u32, h: u32) {
    process_manager::draw(x, y, w, h);
}

pub fn handle_process_manager_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    process_manager::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}

pub fn draw_browser(x: u32, y: u32, w: u32, h: u32) {
    crate::graphics::window::browser::draw(x, y, w, h);
}

pub fn handle_browser_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    crate::graphics::window::browser::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}

pub fn browser_key(ch: u8) {
    crate::graphics::window::browser::browser_key(ch);
}

pub fn browser_special_key(key: SpecialKey) {
    crate::graphics::window::browser::browser_special_key(key);
}

pub fn is_browser_url_focused() -> bool {
    crate::graphics::window::browser::is_url_focused()
}

pub fn draw_wallet(x: u32, y: u32, w: u32, h: u32) {
    wallet::draw(x, y, w, h);
}

pub fn handle_wallet_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    wallet::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}

pub fn wallet_key(ch: u8) {
    wallet::handle_key(ch);
}

pub fn wallet_special_key(key: SpecialKey) {
    wallet::handle_special_key(key);
}

pub fn draw_ecosystem(x: u32, y: u32, w: u32, h: u32) {
    crate::graphics::window::ecosystem::draw(x, y, w, h);
}

pub fn handle_ecosystem_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    crate::graphics::window::ecosystem::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}

pub fn ecosystem_key(ch: u8) {
    crate::graphics::window::ecosystem::handle_key(ch);
}

pub fn ecosystem_special_key(key: SpecialKey) {
    crate::graphics::window::ecosystem::handle_special_key(key);
}

pub fn is_ecosystem_input_focused() -> bool {
    crate::graphics::window::ecosystem::is_input_focused()
}

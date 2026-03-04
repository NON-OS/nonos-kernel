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

use super::{render, input, file, cursor, buffer};
pub use super::input::SpecialKey;

pub fn draw_text_editor(x: u32, y: u32, w: u32, h: u32) {
    render::draw(x, y, w, h);
}

pub fn handle_text_editor_click(win_x: u32, win_y: u32, win_w: u32, win_h: u32, click_x: i32, click_y: i32) -> bool {
    input::handle_click(win_x, win_y, win_w, win_h, click_x, click_y)
}

pub fn editor_key_impl(ch: u8) {
    input::handle_key(ch);
}

pub fn editor_special_key(key: SpecialKey) {
    input::handle_special_key(key);
}

pub fn editor_new() {
    file::new_file();
}

pub fn editor_open(path: &str) {
    file::open_file(path);
}

pub fn editor_save() -> bool {
    file::save_file()
}

pub fn editor_save_as(path: &str) -> bool {
    file::save_file_as(path)
}

pub fn editor_close() {
    file::close_file();
}

pub fn editor_cursor_left() {
    cursor::move_left();
}

pub fn editor_cursor_right() {
    cursor::move_right();
}

pub fn editor_cursor_up() {
    cursor::move_up();
}

pub fn editor_cursor_down() {
    cursor::move_down();
}

pub fn editor_home() {
    cursor::move_to_line_start();
}

pub fn editor_end() {
    cursor::move_to_line_end();
}

pub fn editor_delete() {
    buffer::delete_forward();
}

pub fn editor_copy() -> bool {
    buffer::copy_selection()
}

pub fn editor_cut() -> bool {
    buffer::cut_selection()
}

pub fn editor_paste() -> bool {
    buffer::paste()
}

pub fn editor_select_all() {
    buffer::select_all();
}

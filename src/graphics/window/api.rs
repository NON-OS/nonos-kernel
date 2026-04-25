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

use super::state::{SCROLLBAR_WIDTH, TITLE_BAR_HEIGHT};
use super::text_editor::editor_key_impl;
use super::{dialogs, notifications, scroll, vfs};

pub fn init() {
    vfs::init_vfs();
}

pub fn update_notification_time(time_ms: u64) {
    notifications::update_time(time_ms);
}

pub fn notify_info(message: &[u8]) {
    notifications::info(message);
}

pub fn notify_success(message: &[u8]) {
    notifications::success(message);
}

pub fn notify_warning(message: &[u8]) {
    notifications::warning(message);
}

pub fn notify_error(message: &[u8]) {
    notifications::error(message);
}

pub fn has_notifications() -> bool {
    notifications::has_active()
}

pub fn show_info_dialog(title: &[u8], message: &[u8]) {
    dialogs::show_info(title, message);
}

pub fn show_warning_dialog(title: &[u8], message: &[u8]) {
    dialogs::show_warning(title, message);
}

pub fn show_error_dialog(title: &[u8], message: &[u8]) {
    dialogs::show_error(title, message);
}

pub fn show_confirm_dialog(title: &[u8], message: &[u8]) {
    dialogs::show_confirm(title, message);
}

pub fn show_input_dialog(title: &[u8], message: &[u8], callback_id: u8) {
    dialogs::show_input_dialog(title, message, callback_id);
}

pub fn is_dialog_active() -> bool {
    dialogs::is_active()
}

pub fn is_input_dialog_active() -> bool {
    dialogs::is_input_dialog()
}

pub fn get_dialog_result() -> u8 {
    dialogs::get_result()
}

pub fn get_dialog_input_text() -> &'static str {
    dialogs::get_input_text()
}

pub fn get_dialog_input_callback() -> u8 {
    dialogs::get_input_callback()
}

pub fn close_dialog() {
    dialogs::close();
}

pub fn handle_dialog_key(ch: u8) -> bool {
    dialogs::handle_key(ch)
}

pub mod dialog_result {
    pub use super::dialogs::{RESULT_CANCEL, RESULT_NO, RESULT_NONE, RESULT_OK, RESULT_YES};
}

pub mod dialog_callback {
    pub use super::dialogs::{
        INPUT_CB_DESKTOP_NEW_FILE, INPUT_CB_DESKTOP_NEW_FOLDER, INPUT_CB_FM_NEW_FOLDER,
        INPUT_CB_FM_RENAME, INPUT_CB_NONE,
    };
}

pub fn set_window_content_size(idx: usize, width: u32, height: u32) {
    scroll::set_content_size(idx, width, height);
}

pub fn get_window_scroll(idx: usize) -> (i32, i32) {
    scroll::get_scroll(idx)
}

pub fn scroll_window_by(idx: usize, dx: i32, dy: i32) {
    scroll::scroll_by(idx, dx, dy);
}

pub fn draw_window_scrollbar(idx: usize, x: u32, y: u32, w: u32, h: u32) {
    let content_h = h - TITLE_BAR_HEIGHT;
    if scroll::needs_vertical(idx, content_h) {
        scroll::draw_vertical(idx, x + w - SCROLLBAR_WIDTH, y + TITLE_BAR_HEIGHT, content_h);
    }
}

pub fn editor_key(ch: u8) {
    editor_key_impl(ch);
}

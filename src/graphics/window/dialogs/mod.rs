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

mod input;
mod render;
mod state;

pub(crate) use input::handle_click;
pub(crate) use input::handle_key;
pub(crate) use render::draw;
pub use state::*;

pub fn show_info(title: &[u8], message: &[u8]) {
    state::show_dialog(DIALOG_INFO, title, message);
}
pub fn show_warning(title: &[u8], message: &[u8]) {
    state::show_dialog(DIALOG_WARNING, title, message);
}
pub fn show_error(title: &[u8], message: &[u8]) {
    state::show_dialog(DIALOG_ERROR, title, message);
}
pub fn show_confirm(title: &[u8], message: &[u8]) {
    state::show_dialog(DIALOG_CONFIRM, title, message);
}
pub fn show_input_dialog(title: &[u8], message: &[u8], callback_id: u8) {
    state::show_input(title, message, callback_id);
}

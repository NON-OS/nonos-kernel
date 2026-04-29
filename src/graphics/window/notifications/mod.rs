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

mod actions;
mod icon;
mod input;
mod layout;
mod render;
mod state;
mod storage;
mod timer;
mod types;

pub(crate) use input::handle_click;
pub(crate) use render::draw;
pub(crate) use storage::{has_active, update_time};
pub(crate) use types::{NOTIFY_ERROR, NOTIFY_INFO, NOTIFY_SUCCESS, NOTIFY_WARNING};

pub use actions::{last_action, ACTION_CUSTOM, ACTION_DISMISS, ACTION_OPEN, ACTION_RETRY};
pub use state::{push, push_full, push_with_actions, push_with_title};
pub use types::{PRIORITY_HIGH, PRIORITY_LOW, PRIORITY_NORMAL, PRIORITY_URGENT};

pub fn info(message: &[u8]) {
    state::push(NOTIFY_INFO, message);
}

pub fn success(message: &[u8]) {
    state::push(NOTIFY_SUCCESS, message);
}

pub fn warning(message: &[u8]) {
    state::push(NOTIFY_WARNING, message);
}

pub fn error(message: &[u8]) {
    state::push(NOTIFY_ERROR, message);
}

pub fn info_with_title(title: &[u8], message: &[u8]) {
    state::push_with_title(NOTIFY_INFO, title, message);
}

pub fn error_with_actions(title: &[u8], message: &[u8], actions: &[(&[u8], u8)]) {
    state::push_with_actions(NOTIFY_ERROR, title, message, actions);
}

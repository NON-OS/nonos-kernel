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

pub(super) const MAX_MESSAGE_LEN: usize = 64;
pub(super) const MAX_TITLE_LEN: usize = 32;
pub(super) const MAX_ACTION_LEN: usize = 16;
pub(super) const MAX_ACTIONS: usize = 2;

pub const NOTIFY_INFO: u8 = 0;
pub const NOTIFY_SUCCESS: u8 = 1;
pub const NOTIFY_WARNING: u8 = 2;
pub const NOTIFY_ERROR: u8 = 3;

pub const PRIORITY_LOW: u8 = 0;
pub const PRIORITY_NORMAL: u8 = 1;
pub const PRIORITY_HIGH: u8 = 2;
pub const PRIORITY_URGENT: u8 = 3;

#[derive(Clone, Copy)]
pub(super) struct NotificationAction {
    pub label: [u8; MAX_ACTION_LEN],
    pub label_len: usize,
    pub id: u8,
}

impl NotificationAction {
    pub(super) const fn empty() -> Self {
        Self { label: [0u8; MAX_ACTION_LEN], label_len: 0, id: 0 }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Notification {
    pub active: bool,
    pub ntype: u8,
    pub priority: u8,
    pub title: [u8; MAX_TITLE_LEN],
    pub title_len: usize,
    pub message: [u8; MAX_MESSAGE_LEN],
    pub message_len: usize,
    pub created_at: u64,
    pub actions: [NotificationAction; MAX_ACTIONS],
    pub action_count: u8,
    pub dismissed: bool,
}

impl Notification {
    pub(super) const fn new() -> Self {
        Self {
            active: false,
            ntype: 0,
            priority: PRIORITY_NORMAL,
            title: [0u8; MAX_TITLE_LEN],
            title_len: 0,
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
            created_at: 0,
            actions: [NotificationAction::empty(), NotificationAction::empty()],
            action_count: 0,
            dismissed: false,
        }
    }
}

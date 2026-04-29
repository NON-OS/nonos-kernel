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

use super::storage::{decrement_count, MAX_NOTIFICATIONS, NOTIFICATIONS};
use super::types::{NotificationAction, MAX_ACTION_LEN};
use core::sync::atomic::{AtomicU8, Ordering};

pub(super) const ACTION_NONE: u8 = 0;
pub const ACTION_DISMISS: u8 = 1;
pub const ACTION_OPEN: u8 = 2;
pub const ACTION_RETRY: u8 = 3;
pub const ACTION_CUSTOM: u8 = 4;

static LAST_ACTION: AtomicU8 = AtomicU8::new(ACTION_NONE);
static LAST_ACTION_ID: AtomicU8 = AtomicU8::new(0);

pub(super) fn create_action(label: &[u8], id: u8) -> NotificationAction {
    let mut action = NotificationAction::empty();
    action.id = id;
    action.label_len = label.len().min(MAX_ACTION_LEN);
    for i in 0..action.label_len {
        action.label[i] = label[i];
    }
    action
}

pub(super) fn execute(notification_idx: usize, action_idx: usize) {
    unsafe {
        if notification_idx < MAX_NOTIFICATIONS && NOTIFICATIONS[notification_idx].active {
            let n = &mut NOTIFICATIONS[notification_idx];
            if action_idx < n.action_count as usize {
                let action_id = n.actions[action_idx].id;
                LAST_ACTION.store(action_id, Ordering::Relaxed);
                LAST_ACTION_ID.store(notification_idx as u8, Ordering::Relaxed);
                n.active = false;
                n.dismissed = true;
                decrement_count();
            }
        }
    }
}

pub(super) fn dismiss(notification_idx: usize) {
    unsafe {
        if notification_idx < MAX_NOTIFICATIONS && NOTIFICATIONS[notification_idx].active {
            NOTIFICATIONS[notification_idx].active = false;
            NOTIFICATIONS[notification_idx].dismissed = true;
            decrement_count();
        }
    }
}

pub fn last_action() -> (u8, u8) {
    (LAST_ACTION.load(Ordering::Relaxed), LAST_ACTION_ID.load(Ordering::Relaxed))
}

pub(super) fn clear_last_action() {
    LAST_ACTION.store(ACTION_NONE, Ordering::Relaxed);
}

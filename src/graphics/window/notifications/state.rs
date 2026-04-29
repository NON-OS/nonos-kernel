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

use super::actions::create_action;
use super::storage::{
    current_time, find_free_slot, increment_count, shift_oldest, MAX_NOTIFICATIONS, NOTIFICATIONS,
};
use super::types::{Notification, PRIORITY_NORMAL};

pub fn push(ntype: u8, message: &[u8]) {
    push_full(ntype, PRIORITY_NORMAL, b"", message, &[]);
}

pub fn push_with_title(ntype: u8, title: &[u8], message: &[u8]) {
    push_full(ntype, PRIORITY_NORMAL, title, message, &[]);
}

pub fn push_with_actions(ntype: u8, title: &[u8], message: &[u8], actions: &[(&[u8], u8)]) {
    push_full(ntype, PRIORITY_NORMAL, title, message, actions);
}

pub fn push_full(ntype: u8, priority: u8, title: &[u8], message: &[u8], actions: &[(&[u8], u8)]) {
    let slot = match find_free_slot() {
        Some(s) => s,
        None => {
            shift_oldest();
            MAX_NOTIFICATIONS - 1
        }
    };
    let time = current_time();
    unsafe {
        let n = &mut NOTIFICATIONS[slot];
        *n = Notification::new();
        n.active = true;
        n.ntype = ntype;
        n.priority = priority;
        n.created_at = time;
        let title_max = n.title.len();
        let message_max = n.message.len();
        copy_bytes(&mut n.title, &mut n.title_len, title, title_max);
        copy_bytes(&mut n.message, &mut n.message_len, message, message_max);
        for (i, (label, id)) in actions.iter().take(2).enumerate() {
            n.actions[i] = create_action(label, *id);
            n.action_count += 1;
        }
        increment_count();
    }
}

fn copy_bytes(dest: &mut [u8], len: &mut usize, src: &[u8], max: usize) {
    *len = src.len().min(max);
    for i in 0..*len {
        dest[i] = src[i];
    }
}

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

use super::storage::{
    current_time, decrement_count, DURATION_MS, MAX_NOTIFICATIONS, NOTIFICATIONS,
    URGENT_DURATION_MS,
};
use super::types::PRIORITY_URGENT;

pub(super) fn clear_expired() {
    let time = current_time();
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active && is_expired(&NOTIFICATIONS[i], time) {
                NOTIFICATIONS[i].active = false;
                decrement_count();
            }
        }
    }
}

fn is_expired(n: &super::types::Notification, current: u64) -> bool {
    let duration = if n.priority == PRIORITY_URGENT {
        URGENT_DURATION_MS
    } else {
        DURATION_MS
    };
    current.saturating_sub(n.created_at) > duration
}

pub(super) fn remaining_time(notification_idx: usize) -> u64 {
    let time = current_time();
    unsafe {
        if notification_idx < MAX_NOTIFICATIONS && NOTIFICATIONS[notification_idx].active {
            let n = &NOTIFICATIONS[notification_idx];
            let duration = if n.priority == PRIORITY_URGENT {
                URGENT_DURATION_MS
            } else {
                DURATION_MS
            };
            let elapsed = time.saturating_sub(n.created_at);
            return duration.saturating_sub(elapsed);
        }
    }
    0
}

pub(super) fn progress(notification_idx: usize) -> u8 {
    let time = current_time();
    unsafe {
        if notification_idx < MAX_NOTIFICATIONS && NOTIFICATIONS[notification_idx].active {
            let n = &NOTIFICATIONS[notification_idx];
            let duration = if n.priority == PRIORITY_URGENT {
                URGENT_DURATION_MS
            } else {
                DURATION_MS
            };
            let elapsed = time.saturating_sub(n.created_at);
            let ratio = (elapsed * 100 / duration).min(100);
            return ratio as u8;
        }
    }
    100
}

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

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

pub(crate) const MAX_NOTIFICATIONS: usize = 5;
pub(crate) const MAX_MESSAGE_LEN: usize = 64;
pub(crate) const NOTIFICATION_DURATION_MS: u64 = 5000;

pub(crate) const NOTIFY_INFO: u8 = 0;
pub(crate) const NOTIFY_SUCCESS: u8 = 1;
pub(crate) const NOTIFY_WARNING: u8 = 2;
pub(crate) const NOTIFY_ERROR: u8 = 3;

pub(crate) struct Notification {
    pub(crate) active: bool,
    pub(crate) ntype: u8,
    pub(crate) message: [u8; MAX_MESSAGE_LEN],
    pub(crate) message_len: usize,
    pub(crate) created_at: u64,
}

impl Notification {
    pub(crate) const fn new() -> Self {
        Self {
            active: false,
            ntype: 0,
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
            created_at: 0,
        }
    }
}

pub(crate) static mut NOTIFICATIONS: [Notification; MAX_NOTIFICATIONS] = [
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
];
pub(crate) static NOTIFICATION_COUNT: AtomicU8 = AtomicU8::new(0);
pub(crate) static CURRENT_TIME_MS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn update_time(time_ms: u64) {
    CURRENT_TIME_MS.store(time_ms, Ordering::Relaxed);
}
pub(crate) fn has_active() -> bool {
    NOTIFICATION_COUNT.load(Ordering::Relaxed) > 0
}

pub(crate) fn push(ntype: u8, message: &[u8]) {
    let msg_len = message.len().min(MAX_MESSAGE_LEN);
    let time = CURRENT_TIME_MS.load(Ordering::Relaxed);
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if !NOTIFICATIONS[i].active {
                NOTIFICATIONS[i].active = true;
                NOTIFICATIONS[i].ntype = ntype;
                NOTIFICATIONS[i].message_len = msg_len;
                NOTIFICATIONS[i].created_at = time;
                for j in 0..msg_len {
                    NOTIFICATIONS[i].message[j] = message[j];
                }
                NOTIFICATION_COUNT.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        for i in 0..MAX_NOTIFICATIONS - 1 {
            NOTIFICATIONS[i] = core::mem::replace(&mut NOTIFICATIONS[i + 1], Notification::new());
        }
        let last = MAX_NOTIFICATIONS - 1;
        NOTIFICATIONS[last].active = true;
        NOTIFICATIONS[last].ntype = ntype;
        NOTIFICATIONS[last].message_len = msg_len;
        NOTIFICATIONS[last].created_at = time;
        for j in 0..msg_len {
            NOTIFICATIONS[last].message[j] = message[j];
        }
    }
}

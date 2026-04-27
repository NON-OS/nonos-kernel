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

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Mutex;

pub const SIGEV_NONE: i32 = 0;
pub const SIGEV_SIGNAL: i32 = 1;
pub const SIGEV_THREAD: i32 = 2;

#[derive(Clone, Copy)]
pub struct MqNotification {
    pub notify_type: i32,
    pub signo: i32,
    pub value: u64,
    pub pid: u32,
}

static NOTIFICATIONS: Mutex<BTreeMap<i32, MqNotification>> = Mutex::new(BTreeMap::new());

pub fn register_notification(
    mqdes: i32,
    notify_type: i32,
    signo: i32,
    value: u64,
    pid: u32,
) -> Result<(), i32> {
    let mut notifs = NOTIFICATIONS.lock();
    if notifs.contains_key(&mqdes) {
        return Err(16);
    }
    let notif = MqNotification { notify_type, signo, value, pid };
    notifs.insert(mqdes, notif);
    Ok(())
}

pub fn unregister_notification(mqdes: i32) {
    NOTIFICATIONS.lock().remove(&mqdes);
}

pub fn get_notification(mqdes: i32) -> Option<MqNotification> {
    NOTIFICATIONS.lock().get(&mqdes).copied()
}

pub fn has_notification(mqdes: i32) -> bool {
    NOTIFICATIONS.lock().contains_key(&mqdes)
}

pub fn trigger_notification(mqdes: i32) {
    if let Some(notif) = NOTIFICATIONS.lock().remove(&mqdes) {
        if notif.notify_type == SIGEV_SIGNAL && notif.signo > 0 {
            let _ = crate::syscall::signals::send_signal_to_process(notif.pid, notif.signo as u32);
        }
    }
}

pub fn clear_all_notifications() {
    NOTIFICATIONS.lock().clear();
}

pub fn notification_count() -> usize {
    NOTIFICATIONS.lock().len()
}

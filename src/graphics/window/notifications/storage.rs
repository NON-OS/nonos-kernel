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

use super::types::Notification;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

pub(super) const MAX_NOTIFICATIONS: usize = 8;
pub(super) const DURATION_MS: u64 = 5000;
pub(super) const URGENT_DURATION_MS: u64 = 10000;

pub(super) static mut NOTIFICATIONS: [Notification; MAX_NOTIFICATIONS] = [
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
    Notification::new(),
];
pub(super) static COUNT: AtomicU8 = AtomicU8::new(0);
pub(super) static TIME_MS: AtomicU64 = AtomicU64::new(0);

pub fn update_time(time_ms: u64) {
    TIME_MS.store(time_ms, Ordering::Relaxed);
}

pub(super) fn current_time() -> u64 {
    TIME_MS.load(Ordering::Relaxed)
}

pub(super) fn count() -> u8 {
    COUNT.load(Ordering::Relaxed)
}

pub fn has_active() -> bool {
    count() > 0
}

pub(super) fn increment_count() {
    COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn decrement_count() {
    let current = COUNT.load(Ordering::Relaxed);
    if current > 0 {
        COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) fn find_free_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if !NOTIFICATIONS[i].active {
                return Some(i);
            }
        }
    }
    None
}

pub(super) fn shift_oldest() {
    unsafe {
        for i in 0..MAX_NOTIFICATIONS - 1 {
            NOTIFICATIONS[i] = NOTIFICATIONS[i + 1];
        }
        NOTIFICATIONS[MAX_NOTIFICATIONS - 1] = Notification::new();
    }
}

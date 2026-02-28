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

use core::sync::atomic::Ordering;
use alloc::boxed::Box;

use super::state::{ACTIVE_TIMERS, NEXT_TIMER_ID, TimerCallback};
use super::time::now_ns;

pub fn hrtimer_after_ns<F>(ns: u64, callback: F) -> u64
where
    F: Fn() + Send + Sync + 'static,
{
    let timer_id = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
    let expiry_time = now_ns() + ns;
    let timer_callback = TimerCallback {
        expiry_ns: expiry_time,
        callback: Box::new(callback),
    };
    ACTIVE_TIMERS.lock().insert(timer_id, timer_callback);
    check_expired_timers();
    timer_id
}

pub(crate) fn check_expired_timers() {
    let current_time = now_ns();
    let mut timers = ACTIVE_TIMERS.lock();
    let mut expired_timer_ids = alloc::vec::Vec::new();
    for (&timer_id, timer) in timers.iter() {
        if current_time >= timer.expiry_ns {
            expired_timer_ids.push(timer_id);
        }
    }
    let mut expired_callbacks = alloc::vec::Vec::new();
    for timer_id in expired_timer_ids {
        if let Some(timer) = timers.remove(&timer_id) {
            expired_callbacks.push(timer.callback);
        }
    }
    drop(timers);
    for callback in expired_callbacks {
        callback();
    }
}

pub fn cancel_timer(timer_id: u64) -> bool {
    ACTIVE_TIMERS.lock().remove(&timer_id).is_some()
}

pub fn get_active_timer_count() -> usize {
    ACTIVE_TIMERS.lock().len()
}

pub fn tick() {
    check_expired_timers();
    if let Some(scheduler) = crate::sched::current_scheduler() {
        scheduler.tick();
    }
}

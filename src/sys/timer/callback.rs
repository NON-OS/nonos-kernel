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

use core::sync::atomic::{AtomicU64, Ordering};
use super::uptime::uptime_ms;

const MAX_CALLBACKS: usize = 16;

pub type TimerCallback = fn();

static mut CALLBACKS: [Option<(TimerCallback, u64, u64)>; MAX_CALLBACKS] = [None; MAX_CALLBACKS];
pub static CALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn register_callback(callback: TimerCallback, interval_ms: u64) -> Option<usize> {
    let count = CALLBACK_COUNT.load(Ordering::Relaxed) as usize;
    if count >= MAX_CALLBACKS {
        return None;
    }

    let next_trigger = uptime_ms() + interval_ms;

    unsafe {
        CALLBACKS[count] = Some((callback, interval_ms, next_trigger));
    }

    CALLBACK_COUNT.fetch_add(1, Ordering::SeqCst);
    Some(count)
}

pub fn unregister_callback(id: usize) {
    if id < MAX_CALLBACKS {
        unsafe {
            CALLBACKS[id] = None;
        }
    }
}

pub fn process_callbacks() {
    let now = uptime_ms();
    let count = CALLBACK_COUNT.load(Ordering::Relaxed) as usize;

    for i in 0..count {
        unsafe {
            if let Some((callback, interval, next_trigger)) = CALLBACKS[i] {
                if now >= next_trigger {
                    callback();
                    CALLBACKS[i] = Some((callback, interval, now + interval));
                }
            }
        }
    }
}

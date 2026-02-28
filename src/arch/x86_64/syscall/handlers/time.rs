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

use alloc::collections::BTreeMap;
use spin::Mutex;

extern crate alloc;

/// Per-process alarm state: (pid -> expire_time in milliseconds)
static PROCESS_ALARMS: Mutex<BTreeMap<u32, u64>> = Mutex::new(BTreeMap::new());

pub fn syscall_nanosleep(req: u64, rem: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_nanosleep(req, rem);
    result.value as u64
}

pub fn syscall_sched_yield(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_yield();
    result.value as u64
}

pub fn syscall_clock_gettime(clk_id: u64, tp: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::timer::handle_clock_gettime(clk_id as i32, tp);
    result.value as u64
}

pub fn syscall_gettimeofday(tv: u64, tz: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::handle_gettimeofday(tv, tz);
    result.value as u64
}

/// Implement the alarm syscall.
///
/// Sets an alarm to deliver SIGALRM to the calling process after `seconds` seconds.
/// Returns the number of seconds remaining until any previously scheduled alarm
/// was due to be delivered, or zero if there was no previously scheduled alarm.
pub fn syscall_alarm(seconds: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let pid = crate::process::current_pid().unwrap_or(1);
    let now_ms = crate::time::timestamp_millis();

    let mut alarms = PROCESS_ALARMS.lock();

    // Get remaining time from previous alarm (if any)
    let previous_remaining = if let Some(&expire_time) = alarms.get(&pid) {
        if expire_time > now_ms {
            // Round up to seconds
            ((expire_time - now_ms) + 999) / 1000
        } else {
            0
        }
    } else {
        0
    };

    if seconds == 0 {
        // Cancel any pending alarm
        alarms.remove(&pid);
    } else {
        // Set new alarm expire time
        let expire_time = now_ms + (seconds * 1000);
        alarms.insert(pid, expire_time);
    }

    previous_remaining
}

/// Check and deliver expired alarms. Called from timer interrupt handler.
pub fn check_alarms() {
    let now_ms = crate::time::timestamp_millis();
    let mut expired = alloc::vec::Vec::new();

    {
        let mut alarms = PROCESS_ALARMS.lock();

        // Find expired alarms
        for (&pid, &expire_time) in alarms.iter() {
            if now_ms >= expire_time {
                expired.push(pid);
            }
        }

        // Remove expired alarms
        for pid in &expired {
            alarms.remove(pid);
        }
    }

    // Deliver SIGALRM to expired processes (outside the lock)
    for pid in expired {
        use crate::syscall::signals::constants::SIGALRM;
        let _ = crate::syscall::signals::delivery::send_signal(pid, SIGALRM);
    }
}

/// Cancel alarm for a specific process (called when process exits)
pub fn cancel_process_alarm(pid: u32) {
    PROCESS_ALARMS.lock().remove(&pid);
}

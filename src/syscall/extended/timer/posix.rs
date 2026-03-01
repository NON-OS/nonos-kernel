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
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::syscall::SyscallResult;
use super::super::errno;
use super::constants::*;
use super::types::{Itimerspec, Timespec, Sigevent};
use super::clock::get_clock_time;

pub struct PosixTimer {
    pub clock_id: i32,
    pub notify_type: i32,
    pub signal: i32,
    pub expire_time: u64,
    pub interval: u64,
    pub armed: bool,
    pub overrun: i32,
    pub owner_pid: u32,
}

pub static POSIX_TIMERS: Mutex<BTreeMap<u32, PosixTimer>> = Mutex::new(BTreeMap::new());
static NEXT_TIMER_ID: AtomicU32 = AtomicU32::new(1);

pub fn handle_timer_create(clockid: u64, sevp: u64, timerid_ptr: u64) -> SyscallResult {
    let clockid = clockid as i32;

    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC &&
       clockid != CLOCK_BOOTTIME && clockid != CLOCK_REALTIME_COARSE &&
       clockid != CLOCK_MONOTONIC_COARSE {
        return errno(EINVAL);
    }

    if timerid_ptr == 0 {
        return errno(EFAULT);
    }

    // SAFETY: sevp is user-provided pointer to sigevent struct.
    let (notify_type, signal) = if sevp != 0 {
        let sev = unsafe { *(sevp as *const Sigevent) };
        (sev.sigev_notify, sev.sigev_signo)
    } else {
        (SIGEV_SIGNAL, 14)
    };

    let id = NEXT_TIMER_ID.fetch_add(1, Ordering::SeqCst);

    let mut timers = POSIX_TIMERS.lock();
    if timers.len() >= MAX_POSIX_TIMERS {
        return errno(ENOMEM);
    }

    let pid = crate::process::current_pid().unwrap_or(0);

    let timer = PosixTimer {
        clock_id: clockid,
        notify_type,
        signal,
        expire_time: 0,
        interval: 0,
        armed: false,
        overrun: 0,
        owner_pid: pid,
    };

    timers.insert(id, timer);

    // SAFETY: timerid_ptr is user-provided pointer for timer ID.
    unsafe {
        *(timerid_ptr as *mut u32) = id;
    }

    SyscallResult::success(0)
}

pub fn handle_timer_settime(timerid: i32, flags: i32, new_value: u64, old_value: u64) -> SyscallResult {
    if new_value == 0 {
        return errno(EFAULT);
    }

    // SAFETY: new_value is user-provided pointer to itimerspec struct.
    let new_spec = unsafe { *(new_value as *const Itimerspec) };

    let mut timers = POSIX_TIMERS.lock();
    let timer = match timers.get_mut(&(timerid as u32)) {
        Some(t) => t,
        None => return errno(EINVAL),
    };

    if old_value != 0 {
        let remaining = if timer.armed && timer.expire_time > 0 {
            let now = get_clock_time(timer.clock_id);
            timer.expire_time.saturating_sub(now)
        } else {
            0
        };

        let old_spec = Itimerspec {
            it_value: Timespec::from_nanos(remaining),
            it_interval: Timespec::from_nanos(timer.interval),
        };
        // SAFETY: old_value is user-provided pointer for itimerspec struct.
        unsafe {
            *(old_value as *mut Itimerspec) = old_spec;
        }
    }

    let value_nanos = new_spec.it_value.to_nanos();
    let interval_nanos = new_spec.it_interval.to_nanos();

    if value_nanos == 0 {
        timer.armed = false;
        timer.expire_time = 0;
        timer.interval = 0;
    } else {
        let now = get_clock_time(timer.clock_id);
        timer.expire_time = if (flags & TIMER_ABSTIME) != 0 {
            value_nanos
        } else {
            now + value_nanos
        };
        timer.interval = interval_nanos;
        timer.armed = true;
        timer.overrun = 0;
    }

    SyscallResult::success(0)
}

pub fn handle_timer_gettime(timerid: i32, curr_value: u64) -> SyscallResult {
    if curr_value == 0 {
        return errno(EFAULT);
    }

    let timers = POSIX_TIMERS.lock();
    let timer = match timers.get(&(timerid as u32)) {
        Some(t) => t,
        None => return errno(EINVAL),
    };

    let remaining = if timer.armed && timer.expire_time > 0 {
        let now = get_clock_time(timer.clock_id);
        timer.expire_time.saturating_sub(now)
    } else {
        0
    };

    let spec = Itimerspec {
        it_value: Timespec::from_nanos(remaining),
        it_interval: Timespec::from_nanos(timer.interval),
    };

    // SAFETY: curr_value is user-provided pointer for itimerspec struct.
    unsafe {
        *(curr_value as *mut Itimerspec) = spec;
    }

    SyscallResult::success(0)
}

pub fn handle_timer_getoverrun(timerid: i32) -> SyscallResult {
    let timers = POSIX_TIMERS.lock();
    let timer = match timers.get(&(timerid as u32)) {
        Some(t) => t,
        None => return errno(EINVAL),
    };

    SyscallResult::success(timer.overrun as i64)
}

pub fn handle_timer_delete(timerid: i32) -> SyscallResult {
    let mut timers = POSIX_TIMERS.lock();
    match timers.remove(&(timerid as u32)) {
        Some(_) => SyscallResult::success(0),
        None => errno(EINVAL),
    }
}

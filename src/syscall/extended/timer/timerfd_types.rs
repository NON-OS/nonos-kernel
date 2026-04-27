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

use super::super::errno;
use super::clock::get_clock_time;
use super::constants::*;
use super::types::{Itimerspec, Timespec};
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub struct TimerFd {
    pub clock_id: i32,
    pub flags: i32,
    pub expire_time: u64,
    pub interval: u64,
    pub armed: bool,
    pub expirations: u64,
}

pub static TIMERFD_INSTANCES: Mutex<BTreeMap<u32, TimerFd>> = Mutex::new(BTreeMap::new());
pub static NEXT_TIMERFD_ID: AtomicU32 = AtomicU32::new(1);
pub static FD_TO_TIMERFD: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());

pub fn handle_timerfd_create(clockid: i32, flags: i32) -> SyscallResult {
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC && clockid != CLOCK_BOOTTIME {
        return errno(EINVAL);
    }
    let valid_flags = TFD_CLOEXEC | TFD_NONBLOCK;
    if (flags & !valid_flags) != 0 {
        return errno(EINVAL);
    }
    let id = NEXT_TIMERFD_ID.fetch_add(1, Ordering::SeqCst);
    let mut instances = TIMERFD_INSTANCES.lock();
    if instances.len() >= MAX_TIMERFD {
        return errno(ENOMEM);
    }
    let tfd = TimerFd {
        clock_id: clockid,
        flags,
        expire_time: 0,
        interval: 0,
        armed: false,
        expirations: 0,
    };
    instances.insert(id, tfd);
    match super::timerfd_util::allocate_timerfd(id, flags) {
        Some(fd) => SyscallResult::success(fd as i64),
        None => {
            instances.remove(&id);
            errno(ENOMEM)
        }
    }
}

pub fn handle_timerfd_settime(
    fd: i32,
    flags: i32,
    new_value: u64,
    old_value: u64,
) -> SyscallResult {
    if new_value == 0 {
        return errno(EFAULT);
    }
    let tfd_id = match super::timerfd_util::get_timerfd_id(fd) {
        Some(id) => id,
        None => return errno(EBADF),
    };
    let new_spec: Itimerspec = match read_user_value(new_value) {
        Ok(v) => v,
        Err(_) => return errno(EFAULT),
    };
    let mut instances = TIMERFD_INSTANCES.lock();
    let tfd = match instances.get_mut(&tfd_id) {
        Some(t) => t,
        None => return errno(EBADF),
    };
    if old_value != 0 {
        let remaining = if tfd.armed && tfd.expire_time > 0 {
            get_clock_time(tfd.clock_id)
                .saturating_sub(tfd.expire_time)
                .max(tfd.expire_time.saturating_sub(get_clock_time(tfd.clock_id)))
        } else {
            0
        };
        let old_spec = Itimerspec {
            it_value: Timespec::from_nanos(remaining),
            it_interval: Timespec::from_nanos(tfd.interval),
        };
        if write_user_value(old_value, &old_spec).is_err() {
            return errno(EFAULT);
        }
    }
    let value_nanos = new_spec.it_value.to_nanos();
    let interval_nanos = new_spec.it_interval.to_nanos();
    if value_nanos == 0 {
        tfd.armed = false;
        tfd.expire_time = 0;
        tfd.interval = 0;
        tfd.expirations = 0;
    } else {
        let now = get_clock_time(tfd.clock_id);
        tfd.expire_time =
            if (flags & TFD_TIMER_ABSTIME) != 0 { value_nanos } else { now + value_nanos };
        tfd.interval = interval_nanos;
        tfd.armed = true;
        tfd.expirations = 0;
    }
    SyscallResult::success(0)
}

pub fn handle_timerfd_gettime(fd: i32, curr_value: u64) -> SyscallResult {
    if curr_value == 0 {
        return errno(EFAULT);
    }
    let tfd_id = match super::timerfd_util::get_timerfd_id(fd) {
        Some(id) => id,
        None => return errno(EBADF),
    };
    let instances = TIMERFD_INSTANCES.lock();
    let tfd = match instances.get(&tfd_id) {
        Some(t) => t,
        None => return errno(EBADF),
    };
    let remaining = if tfd.armed && tfd.expire_time > 0 {
        tfd.expire_time.saturating_sub(get_clock_time(tfd.clock_id))
    } else {
        0
    };
    let spec = Itimerspec {
        it_value: Timespec::from_nanos(remaining),
        it_interval: Timespec::from_nanos(tfd.interval),
    };
    if write_user_value(curr_value, &spec).is_err() {
        return errno(EFAULT);
    }
    SyscallResult::success(0)
}

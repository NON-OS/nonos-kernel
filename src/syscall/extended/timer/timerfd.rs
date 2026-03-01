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
use super::types::{Itimerspec, Timespec, TimerFdPollInfo};
use super::clock::get_clock_time;

struct TimerFd {
    clock_id: i32,
    flags: i32,
    expire_time: u64,
    interval: u64,
    armed: bool,
    expirations: u64,
}

static TIMERFD_INSTANCES: Mutex<BTreeMap<u32, TimerFd>> = Mutex::new(BTreeMap::new());
static NEXT_TIMERFD_ID: AtomicU32 = AtomicU32::new(1);
static FD_TO_TIMERFD: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());

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

    match allocate_timerfd(id, flags) {
        Some(fd) => SyscallResult::success(fd as i64),
        None => {
            instances.remove(&id);
            errno(ENOMEM)
        }
    }
}

pub fn handle_timerfd_settime(fd: i32, flags: i32, new_value: u64, old_value: u64) -> SyscallResult {
    if new_value == 0 {
        return errno(EFAULT);
    }

    let tfd_id = match get_timerfd_id(fd) {
        Some(id) => id,
        None => return errno(EBADF),
    };

    // SAFETY: new_value is user-provided pointer to itimerspec struct.
    let new_spec = unsafe { *(new_value as *const Itimerspec) };

    let mut instances = TIMERFD_INSTANCES.lock();
    let tfd = match instances.get_mut(&tfd_id) {
        Some(t) => t,
        None => return errno(EBADF),
    };

    if old_value != 0 {
        let remaining = if tfd.armed && tfd.expire_time > 0 {
            let now = get_clock_time(tfd.clock_id);
            tfd.expire_time.saturating_sub(now)
        } else {
            0
        };

        let old_spec = Itimerspec {
            it_value: Timespec::from_nanos(remaining),
            it_interval: Timespec::from_nanos(tfd.interval),
        };
        // SAFETY: old_value is user-provided pointer for itimerspec struct.
        unsafe {
            *(old_value as *mut Itimerspec) = old_spec;
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
        tfd.expire_time = if (flags & TFD_TIMER_ABSTIME) != 0 {
            value_nanos
        } else {
            now + value_nanos
        };
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

    let tfd_id = match get_timerfd_id(fd) {
        Some(id) => id,
        None => return errno(EBADF),
    };

    let instances = TIMERFD_INSTANCES.lock();
    let tfd = match instances.get(&tfd_id) {
        Some(t) => t,
        None => return errno(EBADF),
    };

    let remaining = if tfd.armed && tfd.expire_time > 0 {
        let now = get_clock_time(tfd.clock_id);
        tfd.expire_time.saturating_sub(now)
    } else {
        0
    };

    let spec = Itimerspec {
        it_value: Timespec::from_nanos(remaining),
        it_interval: Timespec::from_nanos(tfd.interval),
    };

    // SAFETY: curr_value is user-provided pointer for itimerspec struct.
    unsafe {
        *(curr_value as *mut Itimerspec) = spec;
    }

    SyscallResult::success(0)
}

pub fn timerfd_read(tfd_id: u32, blocking: bool) -> Option<u64> {
    loop {
        {
            let mut instances = TIMERFD_INSTANCES.lock();
            if let Some(tfd) = instances.get_mut(&tfd_id) {
                update_timerfd_expirations(tfd);

                if tfd.expirations > 0 {
                    let count = tfd.expirations;
                    tfd.expirations = 0;
                    return Some(count);
                }

                if !blocking || (tfd.flags & TFD_NONBLOCK) != 0 {
                    return None;
                }
            } else {
                return None;
            }
        }

        crate::sched::yield_now();
    }
}

fn update_timerfd_expirations(tfd: &mut TimerFd) {
    if !tfd.armed || tfd.expire_time == 0 {
        return;
    }

    let now = get_clock_time(tfd.clock_id);
    if now >= tfd.expire_time {
        if tfd.interval > 0 {
            let elapsed = now - tfd.expire_time;
            tfd.expirations += 1 + (elapsed / tfd.interval);
            tfd.expire_time += tfd.interval * (1 + elapsed / tfd.interval);
        } else {
            tfd.expirations = 1;
            tfd.armed = false;
        }
    }
}

pub fn get_timerfd_info_for_poll(tfd_id: u32) -> Option<TimerFdPollInfo> {
    let mut instances = TIMERFD_INSTANCES.lock();
    if let Some(tfd) = instances.get_mut(&tfd_id) {
        update_timerfd_expirations(tfd);
        Some(TimerFdPollInfo {
            expirations: tfd.expirations,
        })
    } else {
        None
    }
}

fn allocate_timerfd(tfd_id: u32, flags: i32) -> Option<i32> {
    use crate::process::fd_table;

    let close_on_exec = (flags & TFD_CLOEXEC) != 0;

    let mut entry = fd_table::FdEntry::new(fd_table::FdType::TimerFd, tfd_id as usize);
    entry.flags = if close_on_exec { fd_table::FD_CLOEXEC } else { 0 };
    entry.is_read_end = true;

    let fd = fd_table::allocate_fd(entry)?;

    FD_TO_TIMERFD.lock().insert(fd, tfd_id);

    Some(fd)
}

fn get_timerfd_id(fd: i32) -> Option<u32> {
    if let Some(&id) = FD_TO_TIMERFD.lock().get(&fd) {
        return Some(id);
    }

    use crate::process::fd_table;

    let entry = fd_table::get_fd(fd as u32)?;
    if entry.fd_type != fd_table::FdType::TimerFd {
        return None;
    }
    Some(entry.internal_id as u32)
}

pub fn is_timerfd(fd: i32) -> bool {
    FD_TO_TIMERFD.lock().contains_key(&fd)
}

pub fn fd_to_timerfd_id(fd: i32) -> Option<u32> {
    FD_TO_TIMERFD.lock().get(&fd).copied()
}

pub fn close_timerfd(tfd_id: u32) {
    TIMERFD_INSTANCES.lock().remove(&tfd_id);
}

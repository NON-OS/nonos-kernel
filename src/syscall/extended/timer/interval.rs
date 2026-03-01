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

use crate::syscall::SyscallResult;
use super::super::errno;
use super::constants::*;
use super::types::{Itimerval, Timeval};

pub struct IntervalTimers {
    pub real: Option<IntervalTimer>,
    pub virtual_: Option<IntervalTimer>,
    pub prof: Option<IntervalTimer>,
}

pub struct IntervalTimer {
    pub expire_time: u64,
    pub interval: u64,
    pub start_time: u64,
}

pub static INTERVAL_TIMERS: Mutex<BTreeMap<u32, IntervalTimers>> = Mutex::new(BTreeMap::new());

pub fn handle_getitimer(which: i32, curr_value: u64) -> SyscallResult {
    if which != ITIMER_REAL && which != ITIMER_VIRTUAL && which != ITIMER_PROF {
        return errno(EINVAL);
    }

    if curr_value == 0 {
        return errno(EFAULT);
    }

    let pid = crate::process::current_pid().unwrap_or(0);
    let timers = INTERVAL_TIMERS.lock();

    let itimer = timers.get(&pid).and_then(|t| match which {
        ITIMER_REAL => t.real.as_ref(),
        ITIMER_VIRTUAL => t.virtual_.as_ref(),
        ITIMER_PROF => t.prof.as_ref(),
        _ => None,
    });

    let result = if let Some(timer) = itimer {
        let now = crate::time::timestamp_micros();
        let remaining = timer.expire_time.saturating_sub(now - timer.start_time);
        Itimerval {
            it_value: Timeval {
                tv_sec: (remaining / 1_000_000) as i64,
                tv_usec: (remaining % 1_000_000) as i64,
            },
            it_interval: Timeval {
                tv_sec: (timer.interval / 1_000_000) as i64,
                tv_usec: (timer.interval % 1_000_000) as i64,
            },
        }
    } else {
        Itimerval::default()
    };

    // SAFETY: curr_value is user-provided pointer for itimerval struct.
    unsafe {
        *(curr_value as *mut Itimerval) = result;
    }

    SyscallResult::success(0)
}

pub fn handle_setitimer(which: i32, new_value: u64, old_value: u64) -> SyscallResult {
    if which != ITIMER_REAL && which != ITIMER_VIRTUAL && which != ITIMER_PROF {
        return errno(EINVAL);
    }

    let pid = crate::process::current_pid().unwrap_or(0);

    if old_value != 0 {
        let _ = handle_getitimer(which, old_value);
    }

    if new_value == 0 {
        return errno(EFAULT);
    }

    // SAFETY: new_value is user-provided pointer to itimerval struct.
    let new_val = unsafe { *(new_value as *const Itimerval) };
    let value_usec = new_val.it_value.to_micros();
    let interval_usec = new_val.it_interval.to_micros();

    let mut timers = INTERVAL_TIMERS.lock();
    let proc_timers = timers.entry(pid).or_insert_with(|| IntervalTimers {
        real: None,
        virtual_: None,
        prof: None,
    });

    let timer_slot = match which {
        ITIMER_REAL => &mut proc_timers.real,
        ITIMER_VIRTUAL => &mut proc_timers.virtual_,
        ITIMER_PROF => &mut proc_timers.prof,
        _ => return errno(EINVAL),
    };

    if value_usec == 0 {
        *timer_slot = None;
    } else {
        let now = crate::time::timestamp_micros();
        *timer_slot = Some(IntervalTimer {
            expire_time: value_usec,
            interval: interval_usec,
            start_time: now,
        });
    }

    SyscallResult::success(0)
}

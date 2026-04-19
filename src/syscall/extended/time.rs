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

use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};
use super::errno;

pub fn handle_gettimeofday(tv: u64, _tz: u64) -> SyscallResult {
    if tv != 0 {
        let ms = crate::time::timestamp_millis();
        let tv_sec = (ms / 1000) as i64;
        let tv_usec = ((ms % 1000) * 1000) as i64;

        if write_user_value(tv, &tv_sec).is_err() {
            return errno(14);
        }
        if write_user_value(tv + 8, &tv_usec).is_err() {
            return errno(14);
        }
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_settimeofday(tv: u64, _tz: u64) -> SyscallResult {
    if tv == 0 {
        return errno(14);
    }
    errno(1)
}

pub fn handle_clock_nanosleep(clock_id: u64, flags: u64, request: u64, remain: u64) -> SyscallResult {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
    const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
    const TIMER_ABSTIME: u64 = 1;

    if clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC
        && clock_id != CLOCK_PROCESS_CPUTIME_ID && clock_id != CLOCK_THREAD_CPUTIME_ID {
        return errno(22);
    }

    if request == 0 {
        return errno(14);
    }

    let ts_sec: i64 = match read_user_value(request) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let ts_nsec: i64 = match read_user_value(request + 8) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };

    if ts_sec < 0 || ts_nsec < 0 || ts_nsec >= 1_000_000_000 {
        return errno(22);
    }

    let now_ns = match clock_id {
        CLOCK_REALTIME => crate::time::timestamp_millis() * 1_000_000,
        CLOCK_MONOTONIC => crate::time::now_ns(),
        _ => crate::time::now_ns(),
    };

    let target_ns = if (flags & TIMER_ABSTIME) != 0 {
        (ts_sec as u64) * 1_000_000_000 + (ts_nsec as u64)
    } else {
        now_ns + (ts_sec as u64) * 1_000_000_000 + (ts_nsec as u64)
    };

    let pid = crate::process::current_pid().unwrap_or(0);
    let wake_time_ms = target_ns / 1_000_000;
    crate::sched::scheduler::sleep_until(pid, wake_time_ms);

    if remain != 0 && (flags & TIMER_ABSTIME) == 0 {
        let elapsed_ns = crate::time::now_ns().saturating_sub(now_ns);
        let requested_ns = (ts_sec as u64) * 1_000_000_000 + (ts_nsec as u64);
        let remaining_ns = requested_ns.saturating_sub(elapsed_ns);
        let remain_sec = (remaining_ns / 1_000_000_000) as i64;
        let remain_nsec = (remaining_ns % 1_000_000_000) as i64;
        let _ = write_user_value(remain, &remain_sec);
        let _ = write_user_value(remain + 8, &remain_nsec);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_times(buf: u64) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }

    let ticks = crate::time::current_ticks();
    let ticks_val = ticks as i64;
    let zero: i64 = 0;

    if write_user_value(buf, &ticks_val).is_err() {
        return errno(14);
    }
    let _ = write_user_value(buf + 8, &zero);
    let _ = write_user_value(buf + 16, &zero);
    let _ = write_user_value(buf + 24, &zero);

    SyscallResult { value: ticks as i64, capability_consumed: false, audit_required: false }
}

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
use super::super::errno;
use super::constants::*;
use super::types::Timespec;

pub fn handle_clock_gettime(clockid: i32, tp: u64) -> SyscallResult {
    if tp == 0 {
        return errno(EFAULT);
    }

    let nanos = get_clock_time(clockid);

    let spec = Timespec::from_nanos(nanos);
    // SAFETY: tp is user-provided pointer for timespec struct.
    unsafe {
        *(tp as *mut Timespec) = spec;
    }

    SyscallResult::success(0)
}

pub fn handle_clock_settime(clockid: i32, _tp: u64) -> SyscallResult {
    if clockid != CLOCK_REALTIME {
        return errno(EINVAL);
    }

    errno(1)
}

pub fn handle_clock_getres(clockid: i32, res: u64) -> SyscallResult {
    if res == 0 {
        return SyscallResult::success(0);
    }

    let nanos = match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => 1,
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => 1_000_000,
        _ => return errno(EINVAL),
    };

    let spec = Timespec::from_nanos(nanos);
    // SAFETY: res is user-provided pointer for timespec struct.
    unsafe {
        *(res as *mut Timespec) = spec;
    }

    SyscallResult::success(0)
}

pub fn get_clock_time(clockid: i32) -> u64 {
    match clockid {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            crate::time::timestamp_millis() * 1_000_000
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_COARSE | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => {
            crate::time::uptime_nanos()
        }
        _ => 0,
    }
}

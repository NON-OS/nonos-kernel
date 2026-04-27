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

use super::check::{has_fd_exception, is_fd_readable, is_fd_writable};
use super::types::{FdSet, Timespec, Timeval, EINTR, EINVAL, FD_SETSIZE};
use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_select(
    nfds: i32,
    readfds_ptr: u64,
    writefds_ptr: u64,
    exceptfds_ptr: u64,
    timeout_ptr: u64,
) -> SyscallResult {
    if nfds < 0 || nfds > FD_SETSIZE as i32 {
        return errno(EINVAL);
    }
    let timeout_ms = if timeout_ptr != 0 {
        let timeout: Timeval = match read_user_value(timeout_ptr) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        if timeout.tv_sec < 0 || timeout.tv_usec < 0 {
            return errno(EINVAL);
        }
        let sec_ms = (timeout.tv_sec as u64).saturating_mul(1000);
        Some(sec_ms.saturating_add((timeout.tv_usec as u64) / 1000))
    } else {
        None
    };
    let mut readfds = read_fdset_opt(readfds_ptr);
    let mut writefds = read_fdset_opt(writefds_ptr);
    let mut exceptfds = read_fdset_opt(exceptfds_ptr);
    let result = do_select(nfds, &mut readfds, &mut writefds, &mut exceptfds, timeout_ms);
    write_fdset_opt(readfds_ptr, &readfds);
    write_fdset_opt(writefds_ptr, &writefds);
    write_fdset_opt(exceptfds_ptr, &exceptfds);
    result
}

pub fn handle_pselect6(
    nfds: i32,
    readfds_ptr: u64,
    writefds_ptr: u64,
    exceptfds_ptr: u64,
    timeout_ptr: u64,
    _sigmask_ptr: u64,
) -> SyscallResult {
    if nfds < 0 || nfds > FD_SETSIZE as i32 {
        return errno(EINVAL);
    }
    let timeout_ms = if timeout_ptr != 0 {
        let timeout: Timespec = match read_user_value(timeout_ptr) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        if timeout.tv_sec < 0 || timeout.tv_nsec < 0 || timeout.tv_nsec >= 1_000_000_000 {
            return errno(EINVAL);
        }
        let sec_ms = (timeout.tv_sec as u64).saturating_mul(1000);
        Some(sec_ms.saturating_add((timeout.tv_nsec as u64) / 1_000_000))
    } else {
        None
    };
    let mut readfds = read_fdset_opt(readfds_ptr);
    let mut writefds = read_fdset_opt(writefds_ptr);
    let mut exceptfds = read_fdset_opt(exceptfds_ptr);
    let result = do_select(nfds, &mut readfds, &mut writefds, &mut exceptfds, timeout_ms);
    write_fdset_opt(readfds_ptr, &readfds);
    write_fdset_opt(writefds_ptr, &writefds);
    write_fdset_opt(exceptfds_ptr, &exceptfds);
    result
}

fn read_fdset_opt(ptr: u64) -> Option<FdSet> {
    if ptr == 0 {
        return None;
    }
    read_user_value::<FdSet>(ptr).ok()
}

fn write_fdset_opt(ptr: u64, fds: &Option<FdSet>) {
    if ptr != 0 {
        if let Some(ref fds) = fds {
            let _ = write_user_value(ptr, fds);
        }
    }
}

fn do_select(
    nfds: i32,
    readfds: &mut Option<FdSet>,
    writefds: &mut Option<FdSet>,
    exceptfds: &mut Option<FdSet>,
    timeout_ms: Option<u64>,
) -> SyscallResult {
    let start_time = crate::time::timestamp_millis();
    loop {
        let mut ready_count = 0i32;
        let mut result_read = FdSet::new();
        let mut result_write = FdSet::new();
        let mut result_except = FdSet::new();
        for fd in 0..nfds {
            if let Some(ref fds) = readfds {
                if fds.isset(fd) && is_fd_readable(fd) {
                    result_read.set(fd);
                    ready_count += 1;
                }
            }
            if let Some(ref fds) = writefds {
                if fds.isset(fd) && is_fd_writable(fd) {
                    result_write.set(fd);
                    ready_count += 1;
                }
            }
            if let Some(ref fds) = exceptfds {
                if fds.isset(fd) && has_fd_exception(fd) {
                    result_except.set(fd);
                    ready_count += 1;
                }
            }
        }
        if ready_count > 0 {
            if readfds.is_some() {
                *readfds = Some(result_read);
            }
            if writefds.is_some() {
                *writefds = Some(result_write);
            }
            if exceptfds.is_some() {
                *exceptfds = Some(result_except);
            }
            return SyscallResult::success(ready_count as i64);
        }
        if let Some(ms) = timeout_ms {
            if ms == 0 || crate::time::timestamp_millis().saturating_sub(start_time) >= ms {
                zero_fdsets(readfds, writefds, exceptfds);
                return SyscallResult::success(0);
            }
        }
        if crate::process::signal::has_pending_signals() {
            return errno(EINTR);
        }
        crate::sched::yield_now();
    }
}

fn zero_fdsets(
    readfds: &mut Option<FdSet>,
    writefds: &mut Option<FdSet>,
    exceptfds: &mut Option<FdSet>,
) {
    if let Some(ref mut fds) = readfds {
        fds.zero();
    }
    if let Some(ref mut fds) = writefds {
        fds.zero();
    }
    if let Some(ref mut fds) = exceptfds {
        fds.zero();
    }
}

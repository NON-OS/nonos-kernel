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
use crate::syscall::extended::errno;

use super::types::{
    FdSet, Timeval, Timespec, PollFd, FD_SETSIZE,
    POLLIN, POLLPRI, POLLOUT, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, POLLWRNORM,
    EINVAL, EFAULT, EINTR,
};
use super::check::{
    is_fd_valid, is_fd_readable, is_fd_writable,
    has_fd_exception, has_fd_error, has_fd_hangup, has_fd_priority_data,
};

pub fn handle_select(
    nfds: i32,
    readfds_ptr: u64,
    writefds_ptr: u64,
    exceptfds_ptr: u64,
    timeout_ptr: u64,
) -> SyscallResult {
    if nfds < 0 || nfds > FD_SETSIZE {
        return errno(EINVAL);
    }

    let timeout_ms = if timeout_ptr != 0 {
        let timeout = unsafe { *(timeout_ptr as *const Timeval) };
        if timeout.tv_sec < 0 || timeout.tv_usec < 0 {
            return errno(EINVAL);
        }
        Some((timeout.tv_sec as u64) * 1000 + (timeout.tv_usec as u64) / 1000)
    } else {
        None
    };

    let mut readfds = if readfds_ptr != 0 {
        Some(unsafe { *(readfds_ptr as *const FdSet) })
    } else {
        None
    };
    let mut writefds = if writefds_ptr != 0 {
        Some(unsafe { *(writefds_ptr as *const FdSet) })
    } else {
        None
    };
    let mut exceptfds = if exceptfds_ptr != 0 {
        Some(unsafe { *(exceptfds_ptr as *const FdSet) })
    } else {
        None
    };

    let result = do_select(nfds, &mut readfds, &mut writefds, &mut exceptfds, timeout_ms);

    if let Some(ref fds) = readfds {
        if readfds_ptr != 0 {
            unsafe { *(readfds_ptr as *mut FdSet) = *fds };
        }
    }
    if let Some(ref fds) = writefds {
        if writefds_ptr != 0 {
            unsafe { *(writefds_ptr as *mut FdSet) = *fds };
        }
    }
    if let Some(ref fds) = exceptfds {
        if exceptfds_ptr != 0 {
            unsafe { *(exceptfds_ptr as *mut FdSet) = *fds };
        }
    }

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
    if nfds < 0 || nfds > FD_SETSIZE {
        return errno(EINVAL);
    }

    let timeout_ms = if timeout_ptr != 0 {
        let timeout = unsafe { *(timeout_ptr as *const Timespec) };
        if timeout.tv_sec < 0 || timeout.tv_nsec < 0 || timeout.tv_nsec >= 1_000_000_000 {
            return errno(EINVAL);
        }
        Some((timeout.tv_sec as u64) * 1000 + (timeout.tv_nsec as u64) / 1_000_000)
    } else {
        None
    };

    let mut readfds = if readfds_ptr != 0 {
        Some(unsafe { *(readfds_ptr as *const FdSet) })
    } else {
        None
    };
    let mut writefds = if writefds_ptr != 0 {
        Some(unsafe { *(writefds_ptr as *const FdSet) })
    } else {
        None
    };
    let mut exceptfds = if exceptfds_ptr != 0 {
        Some(unsafe { *(exceptfds_ptr as *const FdSet) })
    } else {
        None
    };

    let result = do_select(nfds, &mut readfds, &mut writefds, &mut exceptfds, timeout_ms);

    if let Some(ref fds) = readfds {
        if readfds_ptr != 0 {
            unsafe { *(readfds_ptr as *mut FdSet) = *fds };
        }
    }
    if let Some(ref fds) = writefds {
        if writefds_ptr != 0 {
            unsafe { *(writefds_ptr as *mut FdSet) = *fds };
        }
    }
    if let Some(ref fds) = exceptfds {
        if exceptfds_ptr != 0 {
            unsafe { *(exceptfds_ptr as *mut FdSet) = *fds };
        }
    }

    result
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
                if fds.isset(fd) {
                    if is_fd_readable(fd) {
                        result_read.set(fd);
                        ready_count += 1;
                    }
                }
            }

            if let Some(ref fds) = writefds {
                if fds.isset(fd) {
                    if is_fd_writable(fd) {
                        result_write.set(fd);
                        ready_count += 1;
                    }
                }
            }

            if let Some(ref fds) = exceptfds {
                if fds.isset(fd) {
                    if has_fd_exception(fd) {
                        result_except.set(fd);
                        ready_count += 1;
                    }
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
            if ms == 0 {
                if let Some(ref mut fds) = readfds {
                    fds.zero();
                }
                if let Some(ref mut fds) = writefds {
                    fds.zero();
                }
                if let Some(ref mut fds) = exceptfds {
                    fds.zero();
                }
                return SyscallResult::success(0);
            }

            let elapsed = crate::time::timestamp_millis().saturating_sub(start_time);
            if elapsed >= ms {
                if let Some(ref mut fds) = readfds {
                    fds.zero();
                }
                if let Some(ref mut fds) = writefds {
                    fds.zero();
                }
                if let Some(ref mut fds) = exceptfds {
                    fds.zero();
                }
                return SyscallResult::success(0);
            }
        }

        if crate::process::signal::has_pending_signals() {
            return errno(EINTR);
        }

        crate::sched::yield_now();
    }
}

pub fn handle_ppoll(
    fds_ptr: u64,
    nfds: u32,
    timeout_ptr: u64,
    _sigmask: u64,
    _sigsetsize: u64,
) -> SyscallResult {
    if fds_ptr == 0 && nfds > 0 {
        return errno(EFAULT);
    }

    let timeout_ms = if timeout_ptr != 0 {
        let timeout = unsafe { *(timeout_ptr as *const Timespec) };
        if timeout.tv_sec < 0 || timeout.tv_nsec < 0 || timeout.tv_nsec >= 1_000_000_000 {
            return errno(EINVAL);
        }
        Some((timeout.tv_sec as u64) * 1000 + (timeout.tv_nsec as u64) / 1_000_000)
    } else {
        None
    };

    do_poll(fds_ptr, nfds, timeout_ms)
}

pub fn handle_poll(fds_ptr: u64, nfds: u32, timeout: i32) -> SyscallResult {
    if fds_ptr == 0 && nfds > 0 {
        return errno(EFAULT);
    }

    let timeout_ms = if timeout < 0 {
        None
    } else {
        Some(timeout as u64)
    };

    do_poll(fds_ptr, nfds, timeout_ms)
}

fn do_poll(fds_ptr: u64, nfds: u32, timeout_ms: Option<u64>) -> SyscallResult {
    let start_time = crate::time::timestamp_millis();

    let pollfds = if nfds > 0 {
        unsafe { core::slice::from_raw_parts_mut(fds_ptr as *mut PollFd, nfds as usize) }
    } else {
        &mut []
    };

    loop {
        let mut ready_count = 0u32;

        for pollfd in pollfds.iter_mut() {
            pollfd.revents = 0;

            if pollfd.fd < 0 {
                continue;
            }

            if !is_fd_valid(pollfd.fd) {
                pollfd.revents = POLLNVAL;
                ready_count += 1;
                continue;
            }

            let mut revents = 0i16;

            if (pollfd.events & (POLLIN | POLLRDNORM)) != 0 {
                if is_fd_readable(pollfd.fd) {
                    revents |= pollfd.events & (POLLIN | POLLRDNORM);
                }
            }

            if (pollfd.events & (POLLOUT | POLLWRNORM)) != 0 {
                if is_fd_writable(pollfd.fd) {
                    revents |= pollfd.events & (POLLOUT | POLLWRNORM);
                }
            }

            if (pollfd.events & POLLPRI) != 0 {
                if has_fd_priority_data(pollfd.fd) {
                    revents |= POLLPRI;
                }
            }

            if has_fd_error(pollfd.fd) {
                revents |= POLLERR;
            }
            if has_fd_hangup(pollfd.fd) {
                revents |= POLLHUP;
            }

            if revents != 0 {
                pollfd.revents = revents;
                ready_count += 1;
            }
        }

        if ready_count > 0 {
            return SyscallResult::success(ready_count as i64);
        }

        if let Some(ms) = timeout_ms {
            if ms == 0 {
                return SyscallResult::success(0);
            }

            let elapsed = crate::time::timestamp_millis().saturating_sub(start_time);
            if elapsed >= ms {
                return SyscallResult::success(0);
            }
        }

        if crate::process::signal::has_pending_signals() {
            return errno(EINTR);
        }

        crate::sched::yield_now();
    }
}

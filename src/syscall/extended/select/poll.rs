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

use super::check::{
    has_fd_error, has_fd_hangup, has_fd_priority_data, is_fd_readable, is_fd_valid, is_fd_writable,
};
use super::types::{
    PollFd, Timespec, EFAULT, EINTR, EINVAL, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI,
    POLLRDNORM, POLLWRNORM,
};
use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user, read_user_value};

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
    do_poll(fds_ptr, nfds, timeout_ms)
}

pub fn handle_poll(fds_ptr: u64, nfds: u32, timeout: i32) -> SyscallResult {
    if fds_ptr == 0 && nfds > 0 {
        return errno(EFAULT);
    }
    let timeout_ms = if timeout < 0 { None } else { Some(timeout as u64) };
    do_poll(fds_ptr, nfds, timeout_ms)
}

fn do_poll(fds_ptr: u64, nfds: u32, timeout_ms: Option<u64>) -> SyscallResult {
    if nfds == 0 {
        return poll_empty(timeout_ms);
    }
    let nfds = (nfds as usize).min(1024);
    let size = match nfds.checked_mul(core::mem::size_of::<PollFd>()) {
        Some(v) => v,
        None => return errno(EINVAL),
    };
    let mut buf = alloc::vec![0u8; size];
    if copy_from_user(fds_ptr, &mut buf).is_err() {
        return errno(EFAULT);
    }
    let mut pollfds: alloc::vec::Vec<PollFd> = (0..nfds)
        .filter_map(|i| {
            let off = i.checked_mul(8)?;
            Some(PollFd {
                fd: i32::from_ne_bytes(buf.get(off..off + 4)?.try_into().ok()?),
                events: i16::from_ne_bytes(buf.get(off + 4..off + 6)?.try_into().ok()?),
                revents: 0,
            })
        })
        .collect();
    let start_time = crate::time::timestamp_millis();
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
            if (pollfd.events & (POLLIN | POLLRDNORM)) != 0 && is_fd_readable(pollfd.fd) {
                revents |= pollfd.events & (POLLIN | POLLRDNORM);
            }
            if (pollfd.events & (POLLOUT | POLLWRNORM)) != 0 && is_fd_writable(pollfd.fd) {
                revents |= pollfd.events & (POLLOUT | POLLWRNORM);
            }
            if (pollfd.events & POLLPRI) != 0 && has_fd_priority_data(pollfd.fd) {
                revents |= POLLPRI;
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
            for (i, pfd) in pollfds.iter().enumerate() {
                let off = match i.checked_mul(8) {
                    Some(v) => v,
                    None => break,
                };
                if let Some(dst) = buf.get_mut(off..off + 8) {
                    dst[0..4].copy_from_slice(&pfd.fd.to_ne_bytes());
                    dst[4..6].copy_from_slice(&pfd.events.to_ne_bytes());
                    dst[6..8].copy_from_slice(&pfd.revents.to_ne_bytes());
                }
            }
            if copy_to_user(fds_ptr, &buf).is_err() {
                return errno(EFAULT);
            }
            return SyscallResult::success(ready_count as i64);
        }
        if let Some(ms) = timeout_ms {
            if ms == 0 || crate::time::timestamp_millis().saturating_sub(start_time) >= ms {
                return SyscallResult::success(0);
            }
        }
        if crate::process::signal::has_pending_signals() {
            return errno(EINTR);
        }
        crate::sched::yield_now();
    }
}

fn poll_empty(timeout_ms: Option<u64>) -> SyscallResult {
    if let Some(ms) = timeout_ms {
        if ms > 0 {
            let start = crate::time::timestamp_millis();
            while crate::time::timestamp_millis().saturating_sub(start) < ms {
                if crate::process::signal::has_pending_signals() {
                    return errno(EINTR);
                }
                crate::sched::yield_now();
            }
        }
    }
    SyscallResult::success(0)
}

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

use core::sync::atomic::Ordering;

use super::check::get_fd_info;
use super::instance::{EpollInstance, EPOLL_INSTANCES, NEXT_EPOLL_ID};
use super::types::*;
use super::util::{allocate_epoll_fd, get_epoll_id};
use crate::syscall::extended::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_to_user, read_user_value};

pub fn handle_epoll_create(size: i32) -> SyscallResult {
    if size <= 0 {
        return errno(EINVAL);
    }
    handle_epoll_create1(0)
}

pub fn handle_epoll_create1(flags: i32) -> SyscallResult {
    if flags != 0 && flags != EPOLL_CLOEXEC {
        return errno(EINVAL);
    }
    let id = NEXT_EPOLL_ID.fetch_add(1, Ordering::SeqCst);
    let mut instances = EPOLL_INSTANCES.lock();
    if instances.len() >= MAX_EPOLL_INSTANCES {
        return errno(ENOMEM);
    }
    let instance = EpollInstance::new();
    instances.insert(id, instance);
    match allocate_epoll_fd(id, flags) {
        Some(fd) => SyscallResult::success(fd as i64),
        None => {
            instances.remove(&id);
            errno(ENOMEM)
        }
    }
}

pub fn handle_epoll_ctl(epfd: i32, op: i32, fd: i32, event_ptr: u64) -> SyscallResult {
    let epoll_id = match get_epoll_id(epfd) {
        Some(id) => id,
        None => return errno(EBADF),
    };
    if epfd == fd {
        return errno(EINVAL);
    }
    if get_fd_info(fd).is_none() {
        return errno(EBADF);
    }
    let event = if op != EPOLL_CTL_DEL {
        if event_ptr == 0 {
            return errno(EFAULT);
        }
        let ev: EpollEvent = match read_user_value(event_ptr) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        Some(ev)
    } else {
        None
    };
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = match instances.get_mut(&epoll_id) {
        Some(i) => i,
        None => return errno(EBADF),
    };
    let result = match op {
        EPOLL_CTL_ADD => match event {
            Some(ev) => instance.add(fd, ev.events, ev.data),
            None => Err(EFAULT),
        },
        EPOLL_CTL_MOD => match event {
            Some(ev) => instance.modify(fd, ev.events, ev.data),
            None => Err(EFAULT),
        },
        EPOLL_CTL_DEL => instance.delete(fd),
        _ => Err(EINVAL),
    };
    match result {
        Ok(()) => SyscallResult::success(0),
        Err(e) => errno(e),
    }
}

pub fn handle_epoll_wait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout: i32,
) -> SyscallResult {
    handle_epoll_pwait(epfd, events_ptr, maxevents, timeout, 0, 0)
}

pub fn handle_epoll_pwait(
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout: i32,
    _sigmask: u64,
    _sigsetsize: u64,
) -> SyscallResult {
    if maxevents <= 0 {
        return errno(EINVAL);
    }
    if events_ptr == 0 {
        return errno(EFAULT);
    }
    let epoll_id = match get_epoll_id(epfd) {
        Some(id) => id,
        None => return errno(EBADF),
    };
    let start_time = crate::time::timestamp_millis();
    let timeout_ms = if timeout < 0 { u64::MAX } else { timeout as u64 };
    loop {
        let ready_events = {
            let mut instances = EPOLL_INSTANCES.lock();
            let instance = match instances.get_mut(&epoll_id) {
                Some(i) => i,
                None => return errno(EBADF),
            };
            instance.poll(maxevents as usize)
        };
        if !ready_events.is_empty() {
            let count = ready_events.len().min(maxevents as usize);
            let buf_size = match count.checked_mul(12) {
                Some(v) => v,
                None => return errno(EINVAL),
            };
            let mut buf = alloc::vec![0u8; buf_size];
            for (i, ev) in ready_events.iter().take(count).enumerate() {
                let off = match i.checked_mul(12) {
                    Some(v) => v,
                    None => break,
                };
                if let Some(dst) = buf.get_mut(off..off + 12) {
                    dst[0..4].copy_from_slice(&ev.events.to_ne_bytes());
                    dst[4..12].copy_from_slice(&ev.data.to_ne_bytes());
                }
            }
            if copy_to_user(events_ptr, &buf).is_err() {
                return errno(EFAULT);
            }
            return SyscallResult::success(count as i64);
        }
        if timeout == 0 {
            return SyscallResult::success(0);
        }
        if crate::time::timestamp_millis().saturating_sub(start_time) >= timeout_ms {
            return SyscallResult::success(0);
        }
        if crate::process::signal::has_pending_signals() {
            return errno(EINTR);
        }
        crate::sched::yield_now();
    }
}

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

use core::sync::atomic::Ordering;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

use super::types::*;
use super::instance::{EpollInstance, EPOLL_INSTANCES, NEXT_EPOLL_ID};
use super::check::get_fd_info;
use super::util::{get_epoll_id, allocate_epoll_fd};

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
        let event_data = unsafe { *(event_ptr as *const EpollEvent) };
        Some(event_data)
    } else {
        None
    };

    let mut instances = EPOLL_INSTANCES.lock();
    let instance = match instances.get_mut(&epoll_id) {
        Some(i) => i,
        None => return errno(EBADF),
    };

    let result = match op {
        EPOLL_CTL_ADD => {
            match event {
                Some(ev) => instance.add(fd, ev.events, ev.data),
                None => Err(EFAULT),
            }
        }
        EPOLL_CTL_MOD => {
            match event {
                Some(ev) => instance.modify(fd, ev.events, ev.data),
                None => Err(EFAULT),
            }
        }
        EPOLL_CTL_DEL => {
            instance.delete(fd)
        }
        _ => Err(EINVAL),
    };

    match result {
        Ok(()) => SyscallResult::success(0),
        Err(e) => errno(e),
    }
}

pub fn handle_epoll_wait(epfd: i32, events_ptr: u64, maxevents: i32, timeout: i32) -> SyscallResult {
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
            let events_slice = unsafe {
                core::slice::from_raw_parts_mut(events_ptr as *mut EpollEvent, count)
            };
            for (i, event) in ready_events.iter().take(count).enumerate() {
                events_slice[i] = *event;
            }
            return SyscallResult::success(count as i64);
        }

        if timeout == 0 {
            return SyscallResult::success(0);
        }

        let elapsed = crate::time::timestamp_millis().saturating_sub(start_time);
        if elapsed >= timeout_ms {
            return SyscallResult::success(0);
        }

        if crate::process::signal::has_pending_signals() {
            return errno(EINTR);
        }

        crate::sched::yield_now();
    }
}

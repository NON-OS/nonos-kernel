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

use super::fd::fd_to_instance_id;
use super::instance::{record_wakeup, EPOLL_INSTANCES};
use super::types::EpollEvent;
use alloc::vec::Vec;

pub fn epoll_poll(epfd: i32, max_events: usize) -> Result<Vec<EpollEvent>, i32> {
    let id = fd_to_instance_id(epfd).ok_or(-9i32)?;
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    let ready = instance.poll(max_events);
    if !ready.is_empty() {
        record_wakeup();
    }
    Ok(ready)
}

pub fn epoll_wait_blocking(
    epfd: i32,
    max_events: usize,
    timeout_ms: i32,
) -> Result<Vec<EpollEvent>, i32> {
    if timeout_ms == 0 {
        return epoll_poll(epfd, max_events);
    }
    let ready = epoll_poll(epfd, max_events)?;
    if !ready.is_empty() || timeout_ms == 0 {
        return Ok(ready);
    }
    Ok(Vec::new())
}

pub fn has_ready_events(epfd: i32) -> bool {
    let id = match fd_to_instance_id(epfd) {
        Some(id) => id,
        None => return false,
    };
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = match instances.get_mut(&id) {
        Some(i) => i,
        None => return false,
    };
    !instance.poll(1).is_empty()
}

pub fn count_ready_events(epfd: i32) -> usize {
    let id = match fd_to_instance_id(epfd) {
        Some(id) => id,
        None => return 0,
    };
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = match instances.get_mut(&id) {
        Some(i) => i,
        None => return 0,
    };
    instance.poll(1024).len()
}

pub fn peek_events(epfd: i32, max: usize) -> Vec<EpollEvent> {
    epoll_poll(epfd, max).unwrap_or_default()
}

pub fn drain_all_events(epfd: i32) -> Vec<EpollEvent> {
    epoll_poll(epfd, 1024).unwrap_or_else(|_| Vec::new())
}

pub fn would_block(epfd: i32) -> bool {
    !has_ready_events(epfd)
}

pub fn can_read(epfd: i32) -> bool {
    has_ready_events(epfd)
}

pub fn epoll_pwait_impl(
    epfd: i32,
    max_events: usize,
    timeout_ms: i32,
    _sigmask: u64,
) -> Result<Vec<EpollEvent>, i32> {
    epoll_wait_blocking(epfd, max_events, timeout_ms)
}

pub fn total_ready_across_all() -> usize {
    let instances = EPOLL_INSTANCES.lock();
    let mut total = 0;
    for (_, instance) in instances.iter() {
        for (fd, entry) in instance.interest_list.iter() {
            if entry.oneshot_triggered && (entry.events & super::types::EPOLLONESHOT) != 0 {
                continue;
            }
            let current_events = super::check::check_fd_events(*fd, entry.events);
            if current_events != 0 {
                total += 1;
            }
        }
    }
    total
}

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
use super::instance::EPOLL_INSTANCES;
use super::types::*;

pub fn epoll_add(epfd: i32, fd: i32, events: u32, data: u64) -> Result<(), i32> {
    let id = fd_to_instance_id(epfd).ok_or(-9i32)?;
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.add(fd, events, data)
}

pub fn epoll_mod(epfd: i32, fd: i32, events: u32, data: u64) -> Result<(), i32> {
    let id = fd_to_instance_id(epfd).ok_or(-9i32)?;
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.modify(fd, events, data)
}

pub fn epoll_del(epfd: i32, fd: i32) -> Result<(), i32> {
    let id = fd_to_instance_id(epfd).ok_or(-9i32)?;
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    instance.delete(fd)
}

pub fn epoll_ctl(epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> Result<(), i32> {
    match op {
        EPOLL_CTL_ADD => epoll_add(epfd, fd, events, data),
        EPOLL_CTL_MOD => epoll_mod(epfd, fd, events, data),
        EPOLL_CTL_DEL => epoll_del(epfd, fd),
        _ => Err(-22),
    }
}

pub fn is_fd_monitored(epfd: i32, fd: i32) -> bool {
    let id = match fd_to_instance_id(epfd) {
        Some(id) => id,
        None => return false,
    };
    let instances = EPOLL_INSTANCES.lock();
    let instance = match instances.get(&id) {
        Some(i) => i,
        None => return false,
    };
    instance.interest_list.contains_key(&fd)
}

pub fn get_fd_events(epfd: i32, fd: i32) -> Option<u32> {
    let id = fd_to_instance_id(epfd)?;
    let instances = EPOLL_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.interest_list.get(&fd).map(|e| e.events)
}

pub fn get_fd_data(epfd: i32, fd: i32) -> Option<u64> {
    let id = fd_to_instance_id(epfd)?;
    let instances = EPOLL_INSTANCES.lock();
    let instance = instances.get(&id)?;
    instance.interest_list.get(&fd).map(|e| e.data)
}

pub fn monitored_fd_count(epfd: i32) -> usize {
    let id = match fd_to_instance_id(epfd) {
        Some(id) => id,
        None => return 0,
    };
    let instances = EPOLL_INSTANCES.lock();
    instances.get(&id).map(|i| i.interest_list.len()).unwrap_or(0)
}

pub fn all_monitored_fds(epfd: i32) -> alloc::vec::Vec<i32> {
    let id = match fd_to_instance_id(epfd) {
        Some(id) => id,
        None => return alloc::vec::Vec::new(),
    };
    let instances = EPOLL_INSTANCES.lock();
    let instance = match instances.get(&id) {
        Some(i) => i,
        None => return alloc::vec::Vec::new(),
    };
    instance.interest_list.keys().copied().collect()
}

pub fn reset_oneshot(epfd: i32, fd: i32) -> Result<(), i32> {
    let id = fd_to_instance_id(epfd).ok_or(-9i32)?;
    let mut instances = EPOLL_INSTANCES.lock();
    let instance = instances.get_mut(&id).ok_or(-9i32)?;
    let entry = instance.interest_list.get_mut(&fd).ok_or(-2i32)?;
    entry.oneshot_triggered = false;
    Ok(())
}

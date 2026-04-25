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

use super::fd::FD_TO_EPOLL;
use super::instance::{total_wakeups, EPOLL_INSTANCES};

pub struct EpollStats {
    pub instance_count: usize,
    pub fd_count: usize,
    pub total_monitored_fds: usize,
    pub total_wakeups: u32,
    pub max_interest_list_size: usize,
}

pub fn get_stats() -> EpollStats {
    let instances = EPOLL_INSTANCES.lock();
    let mut total_monitored = 0;
    let mut max_list_size = 0;
    for inst in instances.values() {
        let size = inst.interest_list.len();
        total_monitored += size;
        if size > max_list_size {
            max_list_size = size;
        }
    }
    EpollStats {
        instance_count: instances.len(),
        fd_count: FD_TO_EPOLL.lock().len(),
        total_monitored_fds: total_monitored,
        total_wakeups: total_wakeups(),
        max_interest_list_size: max_list_size,
    }
}

pub fn instance_stats(fd: i32) -> Option<InstanceStats> {
    let id = super::fd::fd_to_instance_id(fd)?;
    let instances = EPOLL_INSTANCES.lock();
    let instance = instances.get(&id)?;
    Some(InstanceStats {
        id,
        monitored_fd_count: instance.interest_list.len(),
        oneshot_count: instance
            .interest_list
            .values()
            .filter(|e| (e.events & super::types::EPOLLONESHOT) != 0)
            .count(),
        edge_triggered_count: instance
            .interest_list
            .values()
            .filter(|e| (e.events & super::types::EPOLLET) != 0)
            .count(),
    })
}

pub struct InstanceStats {
    pub id: u32,
    pub monitored_fd_count: usize,
    pub oneshot_count: usize,
    pub edge_triggered_count: usize,
}

pub fn total_instances() -> usize {
    EPOLL_INSTANCES.lock().len()
}

pub fn total_fds() -> usize {
    FD_TO_EPOLL.lock().len()
}

pub fn total_monitored_fds() -> usize {
    EPOLL_INSTANCES.lock().values().map(|i| i.interest_list.len()).sum()
}

pub fn memory_usage() -> usize {
    let instances = EPOLL_INSTANCES.lock();
    let mut size = instances.len() * core::mem::size_of::<super::instance::EpollInstance>();
    for inst in instances.values() {
        size += inst.interest_list.len() * core::mem::size_of::<super::instance::EpollEntry>();
    }
    size
}

pub fn get_wakeup_count() -> u32 {
    total_wakeups()
}

pub fn average_interest_list_size() -> usize {
    let instances = EPOLL_INSTANCES.lock();
    if instances.is_empty() {
        return 0;
    }
    let total: usize = instances.values().map(|i| i.interest_list.len()).sum();
    total / instances.len()
}

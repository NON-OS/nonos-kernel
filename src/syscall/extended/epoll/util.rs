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

use alloc::collections::BTreeMap;
use spin::Mutex;

use super::types::EPOLL_CLOEXEC;
use super::instance::EPOLL_INSTANCES;
use super::check::{FdType, get_fd_info};

static FD_TO_EPOLL: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());

pub fn get_epoll_id(fd: i32) -> Option<u32> {
    let info = get_fd_info(fd)?;
    if info.fd_type != FdType::Epoll {
        return None;
    }
    Some(info.internal_id as u32)
}

pub fn allocate_epoll_fd(epoll_id: u32, flags: i32) -> Option<i32> {
    use crate::process::fd_table;

    let close_on_exec = (flags & EPOLL_CLOEXEC) != 0;

    let mut entry = fd_table::FdEntry::new(fd_table::FdType::Epoll, epoll_id as usize);
    entry.flags = if close_on_exec { fd_table::FD_CLOEXEC } else { 0 };

    let fd = fd_table::allocate_fd(entry)?;

    FD_TO_EPOLL.lock().insert(fd, epoll_id);

    Some(fd)
}

pub fn is_epoll_fd(fd: i32) -> bool {
    FD_TO_EPOLL.lock().contains_key(&fd)
}

pub fn fd_to_epoll_id(fd: i32) -> Option<u32> {
    FD_TO_EPOLL.lock().get(&fd).copied()
}

pub fn close_epoll(epoll_id: u32) {
    EPOLL_INSTANCES.lock().remove(&epoll_id);

    let mut fd_map = FD_TO_EPOLL.lock();
    fd_map.retain(|_, &mut id| id != epoll_id);
}

pub fn check_fd_events_external(fd: i32, interest: u32) -> u32 {
    super::check::check_fd_events(fd, interest)
}

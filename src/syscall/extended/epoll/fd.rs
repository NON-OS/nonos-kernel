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

use super::instance::{allocate_epoll_id, EPOLL_INSTANCES};
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

pub static FD_TO_EPOLL: Mutex<BTreeMap<i32, u32>> = Mutex::new(BTreeMap::new());
pub static NEXT_EPOLL_FD: AtomicI32 = AtomicI32::new(0x6000_0000u32 as i32);

pub fn allocate_fd() -> i32 {
    NEXT_EPOLL_FD.fetch_add(1, Ordering::SeqCst)
}

pub fn release_fd(fd: i32) -> Option<u32> {
    FD_TO_EPOLL.lock().remove(&fd)
}

pub fn fd_to_instance_id(fd: i32) -> Option<u32> {
    FD_TO_EPOLL.lock().get(&fd).copied()
}

pub fn is_epoll_fd(fd: i32) -> bool {
    FD_TO_EPOLL.lock().contains_key(&fd)
}

pub fn bind_fd_to_instance(fd: i32, instance_id: u32) {
    FD_TO_EPOLL.lock().insert(fd, instance_id);
}

pub fn all_epoll_fds() -> alloc::vec::Vec<i32> {
    FD_TO_EPOLL.lock().keys().copied().collect()
}

pub fn fd_count() -> usize {
    FD_TO_EPOLL.lock().len()
}

pub fn instance_count() -> usize {
    EPOLL_INSTANCES.lock().len()
}

pub fn validate_fd(fd: i32) -> Result<u32, i32> {
    fd_to_instance_id(fd).ok_or(-9)
}

pub fn create_instance_with_fd(cloexec: bool) -> i32 {
    let id = allocate_epoll_id();
    let instance = super::instance::EpollInstance::new_with_cloexec(cloexec);
    EPOLL_INSTANCES.lock().insert(id, instance);
    let fd = allocate_fd();
    bind_fd_to_instance(fd, id);
    fd
}

pub fn get_interest_list_size(fd: i32) -> usize {
    let id = match fd_to_instance_id(fd) {
        Some(id) => id,
        None => return 0,
    };
    let instances = EPOLL_INSTANCES.lock();
    instances.get(&id).map(|i| i.interest_list.len()).unwrap_or(0)
}

pub fn close_cloexec_fds() -> usize {
    let fds: alloc::vec::Vec<i32> = FD_TO_EPOLL.lock().keys().copied().collect();
    let count = fds.len();
    for fd in fds {
        let _ = super::close::epoll_close(fd);
    }
    count
}

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

use super::instance::{FD_TO_INOTIFY, INOTIFY_INSTANCES, NEXT_FD};
use core::sync::atomic::Ordering;

pub fn allocate_fd() -> i32 {
    let fd = NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32;
    fd
}

pub fn release_fd(fd: i32) -> Option<u32> {
    FD_TO_INOTIFY.lock().remove(&fd)
}

pub fn fd_to_instance_id(fd: i32) -> Option<u32> {
    FD_TO_INOTIFY.lock().get(&fd).copied()
}

pub fn is_inotify_fd(fd: i32) -> bool {
    FD_TO_INOTIFY.lock().contains_key(&fd)
}

pub fn get_instance_by_fd(fd: i32) -> Option<u32> {
    fd_to_instance_id(fd)
}

pub fn all_inotify_fds() -> alloc::vec::Vec<i32> {
    FD_TO_INOTIFY.lock().keys().copied().collect()
}

pub fn fd_count() -> usize {
    FD_TO_INOTIFY.lock().len()
}

pub fn instance_count() -> usize {
    INOTIFY_INSTANCES.lock().len()
}

pub fn bind_fd_to_instance(fd: i32, instance_id: u32) {
    FD_TO_INOTIFY.lock().insert(fd, instance_id);
}

pub fn validate_fd(fd: i32) -> Result<u32, i32> {
    fd_to_instance_id(fd).ok_or(-9)
}

pub fn is_nonblocking(fd: i32) -> bool {
    let id = match fd_to_instance_id(fd) {
        Some(id) => id,
        None => return false,
    };
    let instances = INOTIFY_INSTANCES.lock();
    instances.get(&id).map(|i| i.is_nonblock()).unwrap_or(false)
}

pub fn get_flags(fd: i32) -> Option<i32> {
    let id = fd_to_instance_id(fd)?;
    let instances = INOTIFY_INSTANCES.lock();
    instances.get(&id).map(|i| i.flags)
}

pub fn close_cloexec_fds() -> usize {
    let mut to_close = alloc::vec::Vec::new();
    {
        let fd_map = FD_TO_INOTIFY.lock();
        let instances = INOTIFY_INSTANCES.lock();
        for (&fd, &id) in fd_map.iter() {
            if let Some(inst) = instances.get(&id) {
                if (inst.flags & super::types::IN_CLOEXEC) != 0 {
                    to_close.push(fd);
                }
            }
        }
    }
    let count = to_close.len();
    for fd in to_close {
        let _ = super::util::inotify_close(fd);
    }
    count
}

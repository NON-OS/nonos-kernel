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

use super::instance::{FD_TO_INOTIFY, INOTIFY_INSTANCES};
use alloc::vec::Vec;

pub fn inotify_close(fd: i32) -> Result<(), i32> {
    let id = FD_TO_INOTIFY.lock().remove(&fd).ok_or(-9i32)?;
    INOTIFY_INSTANCES.lock().remove(&id);
    Ok(())
}

pub fn close_all_for_process() -> usize {
    let fds: Vec<i32> = FD_TO_INOTIFY.lock().keys().copied().collect();
    let count = fds.len();
    for fd in fds {
        let _ = inotify_close(fd);
    }
    count
}

pub fn close_if_cloexec(fd: i32) -> bool {
    let id = match FD_TO_INOTIFY.lock().get(&fd).copied() {
        Some(id) => id,
        None => return false,
    };
    let instances = INOTIFY_INSTANCES.lock();
    let is_cloexec =
        instances.get(&id).map(|i| (i.flags & super::types::IN_CLOEXEC) != 0).unwrap_or(false);
    drop(instances);
    if is_cloexec {
        let _ = inotify_close(fd);
        return true;
    }
    false
}

pub fn cleanup_stale() -> usize {
    let instances = INOTIFY_INSTANCES.lock();
    let instance_ids: Vec<u32> = instances.keys().copied().collect();
    drop(instances);
    let mut cleaned = 0;
    for id in instance_ids {
        let has_fd = FD_TO_INOTIFY.lock().values().any(|&v| v == id);
        if !has_fd {
            INOTIFY_INSTANCES.lock().remove(&id);
            cleaned += 1;
        }
    }
    cleaned
}

pub fn is_closed(fd: i32) -> bool {
    !FD_TO_INOTIFY.lock().contains_key(&fd)
}

pub fn force_close(fd: i32) {
    let _ = inotify_close(fd);
}

pub fn close_all() -> usize {
    let fds: Vec<i32> = FD_TO_INOTIFY.lock().keys().copied().collect();
    let count = fds.len();
    for fd in fds {
        let _ = inotify_close(fd);
    }
    count
}

pub fn close_by_instance_id(instance_id: u32) -> usize {
    let mut to_close = Vec::new();
    {
        let fd_map = FD_TO_INOTIFY.lock();
        for (&fd, &id) in fd_map.iter() {
            if id == instance_id {
                to_close.push(fd);
            }
        }
    }
    let count = to_close.len();
    for fd in to_close {
        let _ = inotify_close(fd);
    }
    count
}

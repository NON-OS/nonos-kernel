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

use super::fd::release_fd;
use super::init::{FD_MAP, INSTANCES};

pub fn fanotify_close(fd: i32) -> Result<(), i32> {
    let id = release_fd(fd).ok_or(-9i32)?;
    INSTANCES.lock().remove(&id);
    Ok(())
}

pub fn close_all_for_process(pid: u32) {
    let fd_owner = super::init::FD_OWNER.lock();
    let mut to_close = alloc::vec::Vec::new();
    for (&fd, &owner_pid) in fd_owner.iter() {
        if owner_pid == pid {
            to_close.push(fd);
        }
    }
    drop(fd_owner);
    for fd in to_close {
        super::init::FD_OWNER.lock().remove(&fd);
        let _ = fanotify_close(fd);
    }
}

pub fn close_if_cloexec(fd: i32) -> bool {
    if let Some(instance) = super::fd::fd_to_instance(fd) {
        if (instance.flags & super::FAN_CLOEXEC) != 0 {
            let _ = fanotify_close(fd);
            return true;
        }
    }
    false
}

pub fn cleanup_stale() -> usize {
    let instances = INSTANCES.lock();
    let stale: alloc::vec::Vec<u32> = instances.keys().copied().collect();
    drop(instances);
    let mut cleaned = 0;
    for id in stale {
        let has_fd = FD_MAP.lock().values().any(|&v| v == id);
        if !has_fd {
            INSTANCES.lock().remove(&id);
            cleaned += 1;
        }
    }
    cleaned
}

pub fn is_closed(fd: i32) -> bool {
    !FD_MAP.lock().contains_key(&fd)
}

pub fn force_close(fd: i32) {
    let _ = fanotify_close(fd);
}

pub fn close_all() -> usize {
    let fds: alloc::vec::Vec<i32> = FD_MAP.lock().keys().copied().collect();
    let count = fds.len();
    for fd in fds {
        let _ = fanotify_close(fd);
    }
    count
}

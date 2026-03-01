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

use super::types::{IN_CLOEXEC, IN_NONBLOCK, EINVAL, ENOMEM, EBADF, MAX_INOTIFY_INSTANCES};
use super::instance::{InotifyInstance, INOTIFY_INSTANCES, NEXT_INOTIFY_ID, FD_TO_INOTIFY};
use super::util::allocate_fd;

pub fn handle_inotify_init() -> SyscallResult {
    handle_inotify_init1(0)
}

pub fn handle_inotify_init1(flags: i32) -> SyscallResult {
    let valid_flags = IN_CLOEXEC | IN_NONBLOCK;
    if (flags & !valid_flags) != 0 {
        return errno(EINVAL);
    }

    let instances = INOTIFY_INSTANCES.lock();
    if instances.len() >= MAX_INOTIFY_INSTANCES {
        drop(instances);
        return errno(ENOMEM);
    }
    drop(instances);

    let id = NEXT_INOTIFY_ID.fetch_add(1, Ordering::SeqCst);
    let instance = InotifyInstance::new(id, flags);

    INOTIFY_INSTANCES.lock().insert(id, instance);

    let fd = allocate_fd();
    FD_TO_INOTIFY.lock().insert(fd, id);

    SyscallResult {
        value: fd as i64,
        capability_consumed: false,
        audit_required: false,
    }
}

pub fn handle_inotify_add_watch(fd: i32, pathname: u64, mask: u32) -> SyscallResult {
    if pathname == 0 {
        return errno(EINVAL);
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(EINVAL),
    };

    let inotify_id = match FD_TO_INOTIFY.lock().get(&fd) {
        Some(&id) => id,
        None => return errno(EBADF),
    };

    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get_mut(&inotify_id) {
        Some(inst) => inst,
        None => return errno(EBADF),
    };

    match instance.add_watch(&path, mask) {
        Ok(wd) => SyscallResult {
            value: wd as i64,
            capability_consumed: false,
            audit_required: false,
        },
        Err(e) => errno(e),
    }
}

pub fn handle_inotify_rm_watch(fd: i32, wd: i32) -> SyscallResult {
    let inotify_id = match FD_TO_INOTIFY.lock().get(&fd) {
        Some(&id) => id,
        None => return errno(EBADF),
    };

    let mut instances = INOTIFY_INSTANCES.lock();
    let instance = match instances.get_mut(&inotify_id) {
        Some(inst) => inst,
        None => return errno(EBADF),
    };

    match instance.rm_watch(wd) {
        Ok(_) => SyscallResult::success(0),
        Err(e) => errno(e),
    }
}

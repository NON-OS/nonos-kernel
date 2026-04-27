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

use super::init::FanotifyInstance;
use super::init::{get_instance, FD_MAP, INSTANCES};
use alloc::sync::Arc;

pub fn allocate_fd(instance_id: u32) -> i32 {
    let fd = super::init::NEXT_FD.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    FD_MAP.lock().insert(fd, instance_id);
    fd
}

pub fn release_fd(fd: i32) -> Option<u32> {
    FD_MAP.lock().remove(&fd)
}

pub fn fd_to_instance(fd: i32) -> Option<Arc<FanotifyInstance>> {
    let id = FD_MAP.lock().get(&fd).copied()?;
    get_instance(id)
}

pub fn is_fanotify_fd(fd: i32) -> bool {
    FD_MAP.lock().contains_key(&fd)
}

pub fn get_instance_id(fd: i32) -> Option<u32> {
    FD_MAP.lock().get(&fd).copied()
}

pub fn all_fanotify_fds() -> alloc::vec::Vec<i32> {
    FD_MAP.lock().keys().copied().collect()
}

pub fn instance_count() -> usize {
    INSTANCES.lock().len()
}

pub fn fd_count() -> usize {
    FD_MAP.lock().len()
}

pub fn validate_fd(fd: i32) -> Result<Arc<FanotifyInstance>, i32> {
    fd_to_instance(fd).ok_or(-9)
}

pub fn fd_flags(fd: i32) -> Result<u32, i32> {
    let instance = validate_fd(fd)?;
    Ok(instance.flags)
}

pub fn is_nonblocking(fd: i32) -> bool {
    fd_to_instance(fd).map(|i| (i.flags & super::FAN_NONBLOCK) != 0).unwrap_or(false)
}

pub fn is_cloexec(fd: i32) -> bool {
    fd_to_instance(fd).map(|i| (i.flags & super::FAN_CLOEXEC) != 0).unwrap_or(false)
}

pub fn set_fd_cloexec(fd: i32, _cloexec: bool) -> Result<(), i32> {
    validate_fd(fd)?;
    Ok(())
}

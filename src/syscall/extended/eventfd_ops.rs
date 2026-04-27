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

use super::eventfd_types::*;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

pub fn handle_eventfd(initval: u32) -> SyscallResult {
    super::eventfd_types::handle_eventfd2(initval, 0)
}

pub fn handle_eventfd2(initval: u32, flags: i32) -> SyscallResult {
    super::eventfd_types::handle_eventfd2(initval, flags)
}

pub fn eventfd_read(fd: i32, buf: u64, count: usize) -> Result<usize, i32> {
    if count < 8 {
        return Err(EINVAL);
    }
    let efd_id = match FD_TO_EVENTFD.lock().get(&fd) {
        Some(&id) => id,
        None => return Err(EBADF),
    };
    let instances = EVENTFD_INSTANCES.lock();
    let instance = match instances.get(&efd_id) {
        Some(inst) => inst,
        None => return Err(EBADF),
    };
    let value = instance.read()?;
    drop(instances);
    let value_bytes = value.to_le_bytes();
    if copy_to_user(buf, &value_bytes).is_err() {
        return Err(14);
    }
    Ok(8)
}

pub fn eventfd_write(fd: i32, buf: u64, count: usize) -> Result<usize, i32> {
    if count < 8 {
        return Err(EINVAL);
    }
    let efd_id = match FD_TO_EVENTFD.lock().get(&fd) {
        Some(&id) => id,
        None => return Err(EBADF),
    };
    let mut bytes = [0u8; 8];
    if copy_from_user(buf, &mut bytes).is_err() {
        return Err(14);
    }
    let value = u64::from_le_bytes(bytes);
    let instances = EVENTFD_INSTANCES.lock();
    let instance = match instances.get(&efd_id) {
        Some(inst) => inst,
        None => return Err(EBADF),
    };
    instance.write(value)?;
    drop(instances);
    Ok(8)
}

pub fn eventfd_close(fd: i32) -> Result<(), i32> {
    let efd_id = match FD_TO_EVENTFD.lock().remove(&fd) {
        Some(id) => id,
        None => return Err(EBADF),
    };
    EVENTFD_INSTANCES.lock().remove(&efd_id);
    Ok(())
}

pub struct EventFdInfo {
    pub counter: u64,
    pub is_semaphore: bool,
    pub is_nonblock: bool,
}

pub fn get_eventfd_info(efd_id: usize) -> Option<EventFdInfo> {
    EVENTFD_INSTANCES.lock().get(&(efd_id as u32)).map(|inst| EventFdInfo {
        counter: inst.get_counter(),
        is_semaphore: inst.is_semaphore(),
        is_nonblock: inst.is_nonblock(),
    })
}

pub fn eventfd_is_readable(efd_id: usize) -> bool {
    EVENTFD_INSTANCES
        .lock()
        .get(&(efd_id as u32))
        .map(|inst| inst.get_counter() > 0)
        .unwrap_or(false)
}

pub fn eventfd_is_writable(efd_id: usize) -> bool {
    EVENTFD_INSTANCES
        .lock()
        .get(&(efd_id as u32))
        .map(|inst| inst.get_counter() < EVENTFD_MAX)
        .unwrap_or(false)
}

pub fn fd_to_eventfd_id(fd: i32) -> Option<u32> {
    FD_TO_EVENTFD.lock().get(&fd).copied()
}
pub fn is_eventfd(fd: i32) -> bool {
    FD_TO_EVENTFD.lock().contains_key(&fd)
}
pub fn eventfd_count() -> usize {
    EVENTFD_INSTANCES.lock().len()
}

pub struct EventFdStats {
    pub active_count: usize,
    pub total_counter_sum: u64,
    pub semaphore_mode_count: usize,
    pub nonblock_count: usize,
}

pub fn get_eventfd_stats() -> EventFdStats {
    let instances = EVENTFD_INSTANCES.lock();
    let mut total_counter = 0u64;
    let mut semaphore_count = 0;
    let mut nonblock_count = 0;
    for inst in instances.values() {
        total_counter = total_counter.saturating_add(inst.get_counter());
        if inst.is_semaphore() {
            semaphore_count += 1;
        }
        if inst.is_nonblock() {
            nonblock_count += 1;
        }
    }
    EventFdStats {
        active_count: instances.len(),
        total_counter_sum: total_counter,
        semaphore_mode_count: semaphore_count,
        nonblock_count,
    }
}
